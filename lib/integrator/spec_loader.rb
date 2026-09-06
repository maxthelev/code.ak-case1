# frozen_string_literal: true

require 'json'
require 'yaml'
require 'uri'

module Integrator
  class SpecLoader
    MAX_BYTES = 5 * 1024 * 1024

    def initialize(path)
      @path = File.expand_path(path)
    end

    # читаем yaml или json и проверяем что на входе действительно openapi
    def load
      document = self.class.read_document(@path)
      unless document.is_a?(Hash) && document['openapi'].to_s.match?(/\A3\.[01]\.\d+\z/) && document['paths'].is_a?(Hash)
        raise Error, 'Expected an OpenAPI 3.0.x/3.1.x document with a paths object'
      end
      resolver = RefResolver.new(@path, document)
      result = resolver.resolve
      result['x-integrator-diagnostics'] = resolver.diagnostics
      result
    end

    # проверяем размер до чтения и не принимаем каталоги вместо обычных файлов
    def self.read_document(path, max_bytes: MAX_BYTES)
      raise Error, "Specification must be a regular file: #{path}" unless File.file?(path)
      raise Error, "Specification exceeds #{max_bytes} bytes: #{path}" if File.size(path) > max_bytes

      text = File.read(path, max_bytes + 1, encoding: 'bom|utf-8')
      raise Error, "Specification exceeds #{max_bytes} bytes: #{path}" if text.bytesize > max_bytes
      text.force_encoding(Encoding::UTF_8)
      raise Error, "Specification is not valid UTF-8: #{path}" unless text.valid_encoding?
      yield text.bytesize if block_given?
      data = if File.extname(path).downcase == '.json'
               JSON.parse(text, max_nesting: 128, allow_duplicate_key: false)
             else
               parse_yaml(text)
             end
      json_value!(data)
      data
    rescue Psych::Exception, JSON::ParserError, SystemCallError, EncodingError => error
      raise Error, "Cannot read specification #{path}: #{error.message}"
    end

    # сначала ищем повторные ключи чтобы второй security не затёр первый
    def self.parse_yaml(text)
      text = text.dup.force_encoding(Encoding::UTF_8)
      raise Error, 'YAML is not valid UTF-8' unless text.valid_encoding?

      reject_duplicate_yaml_keys!(YAML.parse_stream(text))
      YAML.safe_load(text, permitted_classes: [], permitted_symbols: [], aliases: false)
    end

    # обход дерева yaml ограничен по глубине ещё до загрузки значений
    def self.reject_duplicate_yaml_keys!(node, depth = 0)
      raise Error, 'YAML nesting exceeds 128 levels' if depth > 130
      if node.is_a?(Psych::Nodes::Mapping)
        keys = {}
        node.children.each_slice(2) do |key, _value|
          raise Error, 'YAML object keys must be scalar strings' unless key.is_a?(Psych::Nodes::Scalar)
          raise Error, "Duplicate YAML key #{key.value.inspect} at line #{key.start_line + 1}" if keys.key?(key.value)
          keys[key.value] = true
        end
      end
      Array(node.children).each { |child| reject_duplicate_yaml_keys!(child, depth + 1) }
    end

    # после yaml оставляем только значения которые можно безопасно записать в json
    def self.json_value!(value, depth = 0)
      raise Error, 'Specification nesting exceeds 128 levels' if depth > 128

      case value
      when Hash
        raise Error, 'Specification object keys must be strings' unless value.keys.all? { |key| key.is_a?(String) }
        value.each_key { |key| json_value!(key, depth + 1) }
        value.each_value { |child| json_value!(child, depth + 1) }
      when Array then value.each { |child| json_value!(child, depth + 1) }
      when Float then raise Error, 'Specification contains a non-finite number' unless value.finite?
      when String
        raise Error, 'Specification contains an invalid UTF-8 string' unless value.dup.force_encoding(Encoding::UTF_8).valid_encoding?
      when Integer, TrueClass, FalseClass, NilClass then nil
      else raise Error, "Unsupported specification value: #{value.class}"
      end
    end
  end

  class RefResolver
    MAX_EXTERNAL_DOCUMENTS = 32
    MAX_EXTERNAL_BYTES = 20 * 1024 * 1024
    MAX_EXPANDED_BYTES = 20 * 1024 * 1024
    NAMED_OBJECTS = %w[properties patternProperties schemas definitions $defs paths pathItems parameters responses headers content requestBodies securitySchemes callbacks links webhooks].freeze
    attr_reader :diagnostics

    def initialize(path, document)
      @path = File.realpath(path)
      @root = File.dirname(@path)
      @documents = { @path => document }
      @diagnostics = []
      @visits = 0
      @external_bytes = 0
      @expanded_bytes = 0
    end

    def resolve
      expand(@documents.fetch(@path), @path, '#', [], 0)
    end

    private

    # считаем весь раскрытый объём а примеры и defaults оставляем обычными данными
    def expand(value, file, pointer, stack, depth, context = :object)
      @visits += 1
      raise Error, 'Expanded specification exceeds 100000 nodes or 128 levels' if @visits > 100_000 || depth > 128
      @expanded_bytes += case value
                         when Hash then 2 + value.keys.sum { |key| JSON.generate(key).bytesize + 2 }
                         when Array then value.length + 2
                         else JSON.generate(value).bytesize
                         end
      raise Error, "Expanded specification exceeds #{MAX_EXPANDED_BYTES} bytes" if @expanded_bytes > MAX_EXPANDED_BYTES

      case value
      when Array
        value.each_with_index.map { |item, index| expand(item, file, "#{pointer}/#{index}", stack, depth + 1, context) }
      when Hash
        return expand_ref(value, file, pointer, stack, depth, context) if value.key?('$ref') && %i[object example].include?(context)

        result = value.to_h do |key, child|
          child_context = if context == :literal then :literal
                          elsif context == :examples then :example
                          elsif context == :named then :object
                          elsif key.start_with?('x-') then :literal
                          elsif %w[example default const enum].include?(key) || (context == :example && key == 'value') then :literal
                          elsif key == 'examples' then child.is_a?(Array) ? :literal : :examples
                          elsif NAMED_OBJECTS.include?(key) && child.is_a?(Hash) then :named
                          else :object
                          end
          [key, expand(child, file, "#{pointer}/#{escape(key)}", stack, depth + 1, child_context)]
        end
        return result unless context == :object
        %w[oneOf anyOf discriminator].each do |keyword|
          diagnostic('unsupported_schema', pointer, "#{keyword} requires an explicit supported schema; alternatives are not guessed") if result.key?(keyword)
        end
        merge_all_of(result, pointer)
      else value
      end
    end

    # раскрываем ref только внутри папки со спекой с учётом кодирования и ссылок
    def expand_ref(value, file, pointer, stack, depth, context)
      reference = value['$ref']
      raise Error, "Invalid $ref at #{pointer}" unless reference.is_a?(String)
      name, fragment = reference.split('#', 2)
      name = URI::RFC2396_PARSER.unescape(name)
      raise Error, "Remote or absolute $ref is not allowed: #{reference}" if name.match?(/\A(?:[a-z][a-z0-9+.-]*:|[\\\/])/i)

      target = name.empty? ? file : File.realpath(File.expand_path(name, File.dirname(file)))
      unless target == @path || target.start_with?(@root + File::SEPARATOR)
        raise Error, "External $ref escapes the specification directory: #{reference}"
      end
      unless @documents.key?(target)
        raise Error, "External references exceed #{MAX_EXTERNAL_DOCUMENTS} documents" if @documents.length - 1 >= MAX_EXTERNAL_DOCUMENTS
        remaining = [SpecLoader::MAX_BYTES, MAX_EXTERNAL_BYTES - @external_bytes].min
        raise Error, "External references exceed #{MAX_EXTERNAL_BYTES} total bytes" if remaining <= 0
        @documents[target] = SpecLoader.read_document(target, max_bytes: remaining) { |bytes| @external_bytes += bytes }
      end
      document = @documents.fetch(target)
      fragment = URI::RFC2396_PARSER.unescape(fragment.to_s)
      key = [target, fragment]
      if stack.include?(key)
        diagnostic('recursive_ref', pointer, "Recursive reference #{reference} cannot be generated safely")
        return { 'x-integrator-unresolved-ref' => reference }
      end
      resolved = expand(at_pointer(document, fragment), target, pointer, stack + [key], depth + 1, context)
      siblings = value.reject { |key_name, _| key_name == '$ref' }
      return resolved if siblings.empty?

      unless resolved.is_a?(Hash)
        raise Error, "$ref with sibling properties must resolve to an object: #{pointer}"
      end
      diagnostic('ref_siblings', pointer, '$ref siblings use OpenAPI 3.1 merge semantics', 'warning')
      resolved.merge(expand(siblings, file, pointer, stack, depth + 1, context))
    rescue SystemCallError, URI::InvalidURIError, ArgumentError => error
      raise Error, "Cannot resolve #{reference} at #{pointer}: #{error.message}"
    end

    # идём по json pointer и отдельно разбираем индексы массивов
    def at_pointer(document, pointer)
      return document if pointer.empty?
      raise Error, "Invalid JSON Pointer ##{pointer}" unless pointer.start_with?('/')

      pointer.split('/', -1).drop(1).reduce(document) do |current, token|
        raise Error, "Invalid JSON Pointer escape in #{token}" if token.match?(/~(?![01])/)
        key = token.gsub('~1', '/').gsub('~0', '~')
        if current.is_a?(Hash) && current.key?(key)
          current[key]
        elsif current.is_a?(Array) && key.match?(/\A(?:0|[1-9]\d*)\z/) && key.to_i < current.length
          current[key.to_i]
        else
          raise Error, "JSON Pointer not found: ##{pointer}"
        end
      end
    end

    # объединяем совместимые части схемы а спорные ограничения оставляем для проверки
    def merge_all_of(schema, pointer)
      return schema unless schema['allOf'].is_a?(Array)

      parts = schema['allOf'] + [schema.reject { |key, _| key == 'allOf' }]
      parts.reduce({}) do |merged, part|
        unless part.is_a?(Hash)
          diagnostic('unsupported_schema', pointer, 'allOf contains a non-object schema')
          next merged
        end
        part.each do |key, value|
          if key == 'properties'
            raise Error, "allOf properties at #{pointer} must be an object" unless value.is_a?(Hash)
            merged[key] ||= {}
            value.each do |name, property|
              if merged[key].key?(name) && merged[key][name] != property
                diagnostic('all_of_conflict', pointer, "Conflicting allOf property #{name} requires manual schema normalization")
              end
              merged[key][name] = property
            end
          elsif key == 'required'
            merged[key] = (Array(merged[key]) + Array(value)).uniq
          else
            if merged.key?(key) && merged[key] != value && !%w[description title example].include?(key)
              diagnostic('all_of_conflict', pointer, "Conflicting allOf constraint #{key} requires manual schema normalization")
            end
            merged[key] = value
          end
        end
        merged
      end
    end

    def diagnostic(code, pointer, message, severity = 'error')
      @diagnostics << { 'severity' => severity, 'code' => code, 'pointer' => pointer, 'message' => message,
                        'action' => 'Normalize the schema or remove unsupported constructs before generation.' }
    end

    def escape(value)
      value.to_s.gsub('~', '~0').gsub('/', '~1')
    end
  end
end
