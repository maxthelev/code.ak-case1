# frozen_string_literal: true

module Integrator
  class Analyzer
    HTTP_METHODS = %w[get post put patch delete head options trace].freeze
    UNSUPPORTED_CONSTRAINTS = %w[not if then else const contains minContains maxContains minProperties maxProperties patternProperties dependentRequired dependentSchemas unevaluatedProperties prefixItems].freeze
    STATUS_RULES = {
      'pending' => 'in_progress', 'processing' => 'in_progress', 'queued' => 'in_progress',
      'completed' => 'approved', 'succeeded' => 'approved', 'success' => 'approved', 'paid' => 'approved', 'settled' => 'approved',
      'failed' => 'rejected', 'cancelled' => 'rejected', 'canceled' => 'rejected', 'rejected' => 'rejected'
    }.freeze
    HTTP_ERRORS = {
      '400' => 'validation_error', '401' => 'invalid_credentials', '402' => 'insufficient_balance',
      '403' => 'forbidden', '404' => 'not_found', '409' => 'conflict', '422' => 'validation_error',
      '429' => 'rate_limit', '500' => 'internal_error', '502' => 'unavailable', '503' => 'unavailable', '504' => 'timeout'
    }.freeze

    def initialize(document, provider:)
      raise Error, 'OpenAPI document must be an object' unless document.is_a?(Hash)
      SpecLoader.json_value!(document)
      @document = document
      @provider = provider
      @diagnostics = Array(document['x-integrator-diagnostics']).map(&:dup)
      @provenance = []
      @mapper = FieldMapper.new
      @text_rules = TextRules.new
      @classifier = OperationClassifier.new
    end

    # собираем методы и правила провайдера а все сомнения сохраняем рядом с результатом
    def analyze
      %w[info components paths].each do |key|
        raise Error, "#{key} must be an object" if @document.key?(key) && !@document[key].is_a?(Hash)
      end
      schemes = @document.dig('components', 'securitySchemes') || {}
      unless schemes.is_a?(Hash) && schemes.values.all? { |scheme| scheme.is_a?(Hash) }
        raise Error, 'securitySchemes must be an object of security scheme objects'
      end
      @servers = validate_servers(@document.fetch('servers', []), '#/servers')
      scan_input_examples(@document)
      if @document.key?('webhooks')
        diagnostic('unsupported_callbacks', '#/webhooks', 'OpenAPI 3.1 top-level webhooks are not converted automatically.', 'Represent the incoming webhook as an explicit path operation.')
      end
      operations = extract_operations
      amount = extract_amount(operations)
      rules = extract_conditions(operations)
      callbacks = operations.select { |operation| operation['role'] == 'webhook' }
      signature = callbacks.empty? ? {} : @text_rules.signature(callbacks.first)
      unless callbacks.empty?
        evidence('signature', 'description', 'medium', callbacks.first['pointer'], 'Signature hints extracted from webhook descriptions; missing details remain unresolved.')
        diagnostic('signature_inferred', callbacks.first['pointer'], 'Signature hints require confirmation of algorithm, signed data and encoding.', 'Set signature in overrides.', 'warning')
      end
      {
        'provider' => @provider, 'title' => @document.dig('info', 'title') || @provider,
        'openapi' => @document['openapi'], 'servers' => @servers,
        'operations' => operations, 'auth_schemes' => @document.dig('components', 'securitySchemes') || {},
        'status_mappings' => extract_statuses(operations), 'error_mappings' => extract_errors(operations),
        'amount' => amount, 'required_if' => rules, 'signature' => signature,
        'request_methods' => { 'create' => 'create', 'status' => 'status', 'check' => 'status', 'cancel' => 'cancel', 'balance' => 'balance' },
        'diagnostics' => @diagnostics, 'provenance' => @provenance
      }
    end

    # после ручной смены роли или полей заново ищем связанные с ними правила
    def recompute_semantics(ir)
      semantic_codes = %w[amount_inferred amount_unresolved conditional_inferred signature_inferred status_inferred status_unmapped status_conflict]
      @diagnostics = ir.fetch('diagnostics', []).reject { |item| semantic_codes.include?(item['code']) || item['stage'] == 'validation' }
      @provenance = ir.fetch('provenance', []).dup
      explicit_statuses = @provenance.any? { |item| item['subject'] == 'status_mappings' && item['source'] == 'override' }
      previous_statuses = explicit_statuses ? ir.fetch('status_mappings', {}) : {}
      explicit_rules = ir.fetch('required_if', []).select { |rule| rule['source'] == 'override' }
      @provenance.reject! do |item|
        item['source'] != 'override' && item['subject'].to_s.match?(/\A(?:amount|signature|required_if\.|status_mappings\.)/)
      end
      # при ручном выборе balance убираем прежние догадки но сохраняем явные сопоставления
      ir.fetch('operations', []).select { |op| op['role'] == 'balance' }.each do |op|
        op['response_mappings'] = op.fetch('response_mappings', {}).select do |canonical, _|
          @provenance.any? { |item| item['source'] == 'override' && item['subject'] == "response_mappings.#{op['id']}.#{canonical}" }
        end
      end
      operations = ir.fetch('operations', []).map do |operation|
        { 'description' => '', 'parameters' => [], 'fields' => [], 'response_fields' => [],
          'field_mappings' => {}, 'response_mappings' => {}, 'responses' => {} }.merge(operation)
      end
      derived_amount = extract_amount(operations)
      ir['amount'] = derived_amount unless ir.dig('amount', 'source') == 'override'
      derived_rules = extract_conditions(operations).reject do |rule|
        explicit_rules.any? { |explicit| explicit['field'] == rule['field'] && explicit['when'] == rule['when'] }
      end
      ir['required_if'] = derived_rules + explicit_rules
      callback = operations.find { |operation| operation['role'] == 'webhook' }
      unless ir.dig('signature', 'source') == 'override'
        ir['signature'] = callback ? @text_rules.signature(callback) : {}
        if callback
          evidence('signature', 'description', 'medium', callback['pointer'], 'Signature hints recomputed for the selected webhook.')
          diagnostic('signature_inferred', callback['pointer'], 'Signature hints require confirmation of algorithm, signed data and encoding.', 'Set signature in overrides.', 'warning')
        end
      end
      ir['status_mappings'] = extract_statuses(operations).merge(previous_statuses)
      ir.fetch('operations', []).each do |operation|
        mappings = operation.fetch('field_mappings', {})
        operation['events'] = operation.fetch('fields', []).select { |field| mappings[field['path']] == 'event' }.flat_map { |field| field.dig('schema', 'enum') || [] }
      end
      ir['diagnostics'] = @diagnostics
      ir['provenance'] = @provenance
      ir
    end

    private

    # берём только http-операции и отмечаем повторяющиеся operationId
    def extract_operations
      operations = @document.fetch('paths', {}).flat_map do |path, path_item|
        raise Error, "Path #{path} must be an object" unless path_item.is_a?(Hash)

        path_item.filter_map do |method, specification|
          next unless HTTP_METHODS.include?(method.downcase)
          build_operation(path, method.downcase, path_item, specification)
        end
      end
      operations.group_by { |operation| operation['id'] }.each do |id, group|
        diagnostic('duplicate_operation_id', '#/paths', "Duplicate operationId #{id} cannot be uniquely overridden.", 'Give each operation a unique operationId.') if group.length > 1
      end
      operations
    end

    # собираем запрос ответы и настройки одного endpoint в общую структуру
    def build_operation(path, method, path_item, specification)
      raise Error, "Operation #{method} #{path} must be an object" unless specification.is_a?(Hash)

      pointer = "#/paths/#{escape(path)}/#{method}"
      %w[operationId summary description].each do |key|
        raise Error, "#{key} at #{pointer} must be a string" if specification.key?(key) && !specification[key].is_a?(String)
      end
      if specification.key?('requestBody') && !specification['requestBody'].is_a?(Hash)
        raise Error, "requestBody at #{pointer} must be an object"
      end
      body = specification.fetch('requestBody', {})
      if body.key?('content') && !body['content'].is_a?(Hash)
        raise Error, "Content at #{pointer}/requestBody/content must be an object"
      end
      security = specification.fetch('security', @document.fetch('security', []))
      unless security.is_a?(Array) && security.all? { |alternative| alternative.is_a?(Hash) && alternative.values.all? { |scopes| scopes.is_a?(Array) } }
        raise Error, "security at #{pointer} must be an array of requirement objects"
      end
      tags = specification.fetch('tags', [])
      raise Error, "tags at #{pointer} must be an array of strings" unless tags.is_a?(Array) && tags.all? { |tag| tag.is_a?(String) }
      if specification.key?('callbacks')
        diagnostic('unsupported_callbacks', "#{pointer}/callbacks", 'OpenAPI callback expressions are not converted automatically.', 'Represent the callback as an explicit incoming path operation.')
      end
      parameters = merge_parameters(path_item.fetch('parameters', []), specification.fetch('parameters', []))
      request = select_media(specification.dig('requestBody', 'content'), "#{pointer}/requestBody/content")
      responses = specification.fetch('responses', {})
      raise Error, "Responses at #{pointer} must be an object" unless responses.is_a?(Hash)
      responses.each do |code, item|
        raise Error, "Response #{code} at #{pointer} must be an object" unless item.is_a?(Hash)
        if item.key?('content') && !item['content'].is_a?(Hash)
          raise Error, "Content at #{pointer}/responses/#{code}/content must be an object"
        end
        select_media(item['content'], "#{pointer}/responses/#{code}/content")
      end

      success_shapes = responses.filter_map do |code, item|
        next unless code.match?(/\A2(?:\d\d|XX)\z/i)
        schema_shape(select_media(item['content'], "#{pointer}/responses/#{code}/content").fetch('schema', {}))
      end
      if success_shapes.uniq.length > 1
        diagnostic('incompatible_success_responses', "#{pointer}/responses", 'Successful responses have different schemas; a single response mapping is not safe.', 'Normalize the 2xx schemas or implement mappings per response before generation.')
      end

      success = responses.keys.find { |code| code.to_s.match?(/\A2(?:\d\d|XX)\z/i) }
      response = select_media(success && responses[success]['content'], "#{pointer}/responses/#{success}/content")
      request_media = json_media_key(specification.dig('requestBody', 'content') || {})
      response_media = json_media_key(success ? (responses[success]['content'] || {}) : {})
      operation = {
        'id' => specification['operationId'] || "#{method}_#{path.gsub(/[^a-zA-Z0-9]+/, '_').sub(/_\z/, '')}",
        'path' => path, 'method' => method, 'pointer' => pointer,
        'summary' => specification['summary'].to_s, 'description' => specification['description'].to_s,
        'tags' => tags,
        'servers' => if specification.key?('servers')
                       validate_servers(specification['servers'], "#{pointer}/servers")
                     elsif path_item.key?('servers')
                       validate_servers(path_item['servers'], "#/paths/#{escape(path)}/servers")
                     else @servers
                     end,
        'security' => security,
        'parameters' => parameters, 'request' => request, 'responses' => responses,
        'request_media_type' => request_media, 'response_media_type' => response_media,
        'fields' => flatten(request['schema'], "#{pointer}/requestBody/content/#{escape(request_media)}/schema"),
        'response_fields' => flatten(response['schema'], "#{pointer}/responses/#{success}/content/#{escape(response_media)}/schema")
      }
      operation.merge!(@classifier.classify(operation))
      evidence("operations.#{operation['id']}.role", 'heuristic', operation['confidence'], pointer, "Semantic scoring selected #{operation['role']}.")
      if operation['confidence'] != 'high'
        diagnostic('operation_ambiguous', pointer, "Role for #{operation['id']} is #{operation['role']} (#{operation['confidence']}).", "Set operations.#{operation['id']} in overrides.", operation['role'] == 'unknown' ? 'error' : 'warning')
      end
      operation['field_mappings'] = map_fields(operation['fields'], operation, operation['role'] == 'webhook')
      parameters.each do |parameter|
        field = { 'path' => parameter['name'], 'schema' => parameter.fetch('schema', {}).merge('description' => parameter['description'].to_s) }
        canonical = @mapper.canonical(field, response: true)
        operation['field_mappings'][parameter['name']] = canonical if canonical
      end
      operation['response_mappings'] = map_fields(operation['response_fields'], operation, true).invert
      operation['idempotency'] = @text_rules.idempotency(parameters, operation['description'])
      if operation['idempotency']
        source = parameters.any? { |parameter| parameter['name'] == operation['idempotency']['name'] } ? 'structure' : 'description'
        evidence("#{operation['id']}.idempotency", source, source == 'structure' ? 'high' : 'medium', pointer, "Idempotency #{operation['idempotency']}.")
        diagnostic('idempotency_inferred', pointer, 'Idempotency header extracted from description.', 'Confirm idempotency in overrides.', 'warning') if source == 'description'
      end
      operation['events'] = operation['fields'].select { |field| operation['field_mappings'][field['path']] == 'event' }.flat_map { |field| field.dig('schema', 'enum') || [] }
      operation
    end

    # параметр метода заменяет общий только при совпадении имени и места передачи
    def merge_parameters(inherited, local)
      unless inherited.is_a?(Array) && local.is_a?(Array) && (inherited + local).all? { |parameter| parameter.is_a?(Hash) }
        raise Error, 'Operation parameters must be an array of objects'
      end
      (inherited + local).each_with_object({}) do |parameter, result|
        unless parameter['name'].is_a?(String) && %w[path query header cookie].include?(parameter['in'])
          raise Error, 'Every parameter needs a string name and path/query/header/cookie location'
        end
        if parameter.key?('schema')
          raise Error, 'Parameter schema must be an object' unless parameter['schema'].is_a?(Hash)
          inspect_schema(parameter['schema'], '#/parameters/' + escape(parameter['name']))
        end
        result[[parameter['in'], parameter['name']]] = parameter
      end.values
    end

    # выбираем json из content а неподдерживаемый формат отмечаем как ошибку
    def select_media(content, pointer)
      return {} unless content
      raise Error, "Content at #{pointer} must be an object" unless content.is_a?(Hash)
      content.each do |name, media|
        raise Error, "Media object at #{pointer}/#{name} must be an object" unless media.is_a?(Hash)
      end

      key = json_media_key(content)
      unless key
        diagnostic('unsupported_media_type', pointer, "Only JSON request/response media are generated; found #{content.keys.join(', ')}.", 'Convert to JSON or implement a media adapter.')
        return {}
      end
      media = content.fetch(key)
      if media.key?('examples') && !(media['examples'].is_a?(Hash) && media['examples'].values.all? { |example| example.is_a?(Hash) })
        raise Error, "Media examples at #{pointer}/#{key} must be an object of example objects"
      end
      inspect_schema(media['schema'], "#{pointer}/#{escape(key)}/schema") if media.key?('schema')
      media
    end

    def json_media_key(content)
      content.keys.find { |name| name.downcase == 'application/json' } || content.keys.find { |name| name.match?(%r{\Aapplication/[^;]+\+json\z}i) }
    end

    # проверяем ограничения которые готовый сервис сможет выполнить
    def inspect_schema(schema, pointer)
      unless schema.is_a?(Hash)
        diagnostic('unsupported_schema', pointer, 'Only object-form schemas are supported.', 'Replace boolean schemas with an explicit typed schema.')
        return
      end
      %w[properties].each do |key|
        raise Error, "Schema #{key} at #{pointer} must be an object" if schema.key?(key) && !schema[key].is_a?(Hash)
      end
      %w[required enum].each do |key|
        raise Error, "Schema #{key} at #{pointer} must be an array" if schema.key?(key) && !schema[key].is_a?(Array)
      end
      validate_constraint_types(schema, pointer)
      UNSUPPORTED_CONSTRAINTS.each do |keyword|
        next unless schema.key?(keyword)
        diagnostic('unsupported_schema', pointer, "Constraint #{keyword} is preserved but not enforced by the generated runtime.", 'Simplify this schema or add runtime support before production use.')
      end
      if schema['type'].is_a?(Array) || schema.key?('additionalProperties')
        diagnostic('unsupported_schema', pointer, 'Union types and additionalProperties constraints need a specialized schema adapter.', 'Use an explicit object schema with supported field types.')
      end
      schema.fetch('properties', {}).each { |name, child| inspect_schema(child, "#{pointer}/properties/#{escape(name)}") }
      inspect_schema(schema['items'], "#{pointer}/items") if schema.key?('items')
    end

    # не даём строкам вроде nullable: "false" притвориться булевыми значениями
    def validate_constraint_types(schema, pointer)
      %w[nullable uniqueItems readOnly writeOnly deprecated].each do |keyword|
        next unless schema.key?(keyword)
        next if schema[keyword] == true || schema[keyword] == false
        diagnostic('invalid_schema', pointer, "Schema #{keyword} must be boolean.", "Set #{keyword} to true or false.")
      end
      types = %w[object array string number integer boolean null]
      if schema.key?('type') && !(Array(schema['type']) - types).empty?
        raise Error, "Schema type at #{pointer} must be a recognized JSON type"
      end
      if schema.key?('required') && !schema['required'].all? { |name| name.is_a?(String) }
        raise Error, "Schema required at #{pointer} must contain property names"
      end
      %w[minimum maximum multipleOf].each do |key|
        next unless schema.key?(key)
        valid = schema[key].is_a?(Numeric) && schema[key].finite?
        valid &&= schema[key].positive? if key == 'multipleOf'
        raise Error, "Schema #{key} at #{pointer} must be a #{key == 'multipleOf' ? 'positive ' : ''}finite number" unless valid
      end
      %w[exclusiveMinimum exclusiveMaximum].each do |key|
        next unless schema.key?(key)
        value = schema[key]
        unless value == true || value == false || (value.is_a?(Numeric) && value.finite?)
          raise Error, "Schema #{key} at #{pointer} must be boolean or numeric"
        end
      end
      %w[minLength maxLength minItems maxItems].each do |key|
        next unless schema.key?(key)
        raise Error, "Schema #{key} at #{pointer} must be a nonnegative integer" unless schema[key].is_a?(Integer) && schema[key] >= 0
      end
      return unless schema.key?('pattern')
      raise Error, "Schema pattern at #{pointer} must be a string" unless schema['pattern'].is_a?(String)
      Regexp.new(schema['pattern'])
    rescue RegexpError
      diagnostic('unsupported_pattern', pointer, 'Schema pattern is not supported by Ruby regular expressions.', 'Use a compatible expression or add a validator adapter.')
    end

    # разворачиваем вложенные свойства в пути и сохраняем обязательность родителей
    def flatten(schema, pointer, prefix = '', required = true)
      return [] if schema.nil?
      unless schema.is_a?(Hash)
        diagnostic('unsupported_schema', pointer, 'Only object-form schemas are supported.', 'Replace boolean schemas with an explicit typed schema.')
        return []
      end

      properties = schema['properties']
      return [] unless properties.is_a?(Hash)

      properties.flat_map do |name, definition|
        raise Error, "Property #{name} at #{pointer} must be a schema object" unless definition.is_a?(Hash)

        path = [prefix, name].reject(&:empty?).join('.')
        child_pointer = "#{pointer}/properties/#{escape(name)}"
        child_required = required && Array(schema['required']).include?(name)
        if definition['properties'].is_a?(Hash) && !definition['properties'].empty?
          flatten(definition, child_pointer, path, child_required)
        else
          [{ 'path' => path, 'schema' => definition, 'required' => child_required, 'pointer' => child_pointer }]
        end
      end
    end

    # пробуем знакомые названия полей а неоднозначные варианты не выбираем молча
    def map_fields(fields, operation, response)
      # для баланса нет общего платёжного формата ответа поэтому сохраняем поля провайдера
      return {} if response && operation['role'] == 'balance'

      fields.each_with_object({}) do |field, mappings|
        canonical = @mapper.canonical(field, response: response)
        if canonical
          if mappings.value?(canonical)
            diagnostic('field_ambiguous', field['pointer'], "Multiple fields map to #{canonical} in #{operation['id']}.", 'Set field_mappings or response_mappings in overrides.')
          end
          mappings[field['path']] = canonical
          evidence("#{operation['id']}.#{response ? 'response' : 'request'}.#{field['path']}", 'heuristic', @mapper.alias?(field) ? 'high' : 'medium', field['pointer'], "Field#{' alias' if @mapper.alias?(field)} mapped to #{canonical}.")
        elsif response && @mapper.alias?(field)
          diagnostic('ambiguous_response_field', field['pointer'], "Context of #{field['path']} does not identify a payment field.", "Set response_mappings.#{operation['id']} if this field belongs to the payment.", 'warning')
        elsif !response
          diagnostic('field_unmapped', field['pointer'], "No canonical mapping for #{field['path']}.", "Set field_mappings.#{operation['id']}.#{field['path']} or supply a schema default.", field['required'] ? 'error' : 'warning')
        end
      end
    end

    # ищем единицы только у денежных полей чтобы не перепутать сумму с комиссией
    def extract_amount(operations)
      findings = operations.select { |operation| operation['role'] == 'create' }.flat_map do |operation|
        amount_fields = operation['fields'].select { |field| operation['field_mappings'][field['path']] == 'amount' }
        texts = amount_fields.map { |field| [field.dig('schema', 'description').to_s, field['pointer']] }
        texts << [operation['description'], operation['pointer']]
        texts.flat_map do |text, pointer|
          @text_rules.units(text).map do |unit|
            evidence('amount', 'description', 'medium', pointer, "Amount unit #{unit['unit']} with factor #{unit['factor'].inspect} extracted from text.")
            unit
          end
        end
      end.uniq
      if findings.length == 1
        diagnostic('amount_inferred', '#/amount', 'Amount units were inferred from descriptions; verify the factor for this currency.', 'Confirm amount.unit and amount.factor in overrides.', 'warning')
        findings.first
      else
        diagnostic('amount_unresolved', '#/amount', findings.empty? ? 'Amount unit is not specified.' : 'Conflicting amount units were found.', 'Set amount.unit and amount.factor in overrides.')
        { 'unit' => nil, 'factor' => nil }
      end
    end

    # проверяем форму адресов а шаблоны server variables просим раскрыть вручную
    def validate_servers(servers, pointer)
      unless servers.is_a?(Array)
        diagnostic('invalid_server', pointer, 'servers must be an array.', 'Provide server objects with HTTP(S) url strings.')
        return []
      end
      servers.filter_map.with_index do |server, index|
        location = "#{pointer}/#{index}"
        unless server.is_a?(Hash) && server['url'].is_a?(String) && !server['url'].empty?
          diagnostic('invalid_server', location, 'Server must be an object with a nonempty url string.', 'Provide an HTTP(S) base URL.')
          next
        end
        if server.key?('variables') || server['url'].match?(/[{}]/)
          diagnostic('unsupported_server_variables', location, 'Server variables are not expanded.', 'Replace variables with an explicit base URL.')
        else
          begin
            uri = URI.parse(server['url'])
            unless %w[http https].include?(uri.scheme) && uri.host && !uri.userinfo && !uri.query && !uri.fragment
              diagnostic('invalid_server', location, 'Server URL must use HTTP(S) without userinfo, query or fragment.', 'Provide a plain HTTP(S) base URL.')
            end
            diagnostic('insecure_transport', location, 'HTTP does not encrypt requests or credentials.', 'Use HTTPS when supported by the provider.', 'warning') if uri.scheme == 'http'
          rescue URI::InvalidURIError
            diagnostic('invalid_server', location, 'Server URL is malformed.', 'Provide an HTTP(S) base URL.')
          end
        end
        server
      end
    end

    # для сравнения ответов убираем пояснения но оставляем ограничения схемы
    def schema_shape(schema)
      return schema unless schema.is_a?(Hash)
      result = schema.reject { |key, _| %w[description title example examples].include?(key) }
      result['properties'] = schema['properties'].transform_values { |child| schema_shape(child) } if schema['properties'].is_a?(Hash)
      result['items'] = schema_shape(schema['items']) if schema.key?('items')
      result
    end

    # предупреждаем о похожих на credentials примерах не выводя их значения
    def scan_input_examples(value, pointer = '#', literal = false)
      case value
      when Hash
        value.each do |key, child|
          location = "#{pointer}/#{escape(key)}"
          credential_key = %w[authorization api_key access_token client_secret password callback_secret].include?(key.downcase.tr('-', '_'))
          schema_literal = pointer.end_with?('/properties') && child.is_a?(Hash) && %w[default example examples].any? { |name| child.key?(name) && !child[name].nil? }
          if credential_key && ((literal && !child.nil?) || schema_literal)
            diagnostic('input_credential_example', location, 'Input example/default contains a credential-like key.', 'Review the input: its values are preserved in generated artifacts. Replace real credentials with test data.', 'warning')
          end
          scan_input_examples(child, location, literal || %w[example examples default].include?(key))
        end
      when Array then value.each_with_index { |child, index| scan_input_examples(child, "#{pointer}/#{index}", literal) }
      end
    end

    # ищем условия реквизитов в описании метода и отдельных полей
    def extract_conditions(operations)
      operations.select { |operation| operation['role'] == 'create' }.flat_map do |operation|
        field_rules = operation['fields'].filter_map do |field|
          rule = @text_rules.required_if(field)
          next unless rule

          evidence("required_if.#{field['path']}", 'description', 'medium', field['pointer'], "#{field['path']} required when #{rule['when']}.")
          diagnostic('conditional_inferred', field['pointer'], "Conditional requirement extracted for #{field['path']}.", 'Confirm required_if in overrides.', 'warning')
          rule
        end
        description_rules = @text_rules.operation_conditions(operation)
        description_rules.each do |rule|
          evidence("required_if.#{rule['field']}", 'description', 'medium', operation['pointer'], "#{rule['field']} required when #{rule['when']}.")
          diagnostic('conditional_inferred', operation['pointer'], "Conditional requirement extracted for #{rule['field']}.", 'Confirm required_if in overrides.', 'warning')
        end
        field_rules + description_rules
      end.uniq
    end

    # сопоставляем статусы и отмечаем противоречия между разными ответами
    def extract_statuses(operations)
      fields = operations.flat_map do |operation|
        operation['fields'].select { |field| operation['field_mappings'][field['path']] == 'status' } +
          response_status_fields(operation)
      end
      fields.each_with_object({}) do |field, mappings|
        Array(field.dig('schema', 'enum')).each do |status|
          from_text = @text_rules.status_meaning(status, field.dig('schema', 'description'))
          canonical = from_text.nil? ? STATUS_RULES[status.to_s.downcase] : from_text
          if canonical
            if mappings.key?(status.to_s) && mappings[status.to_s] != canonical
              diagnostic('status_conflict', field['pointer'], "Conflicting meanings for status #{status}.", 'Normalize status descriptions or set an explicit status mapping.', 'error', {'status' => status.to_s})
            end
            mappings[status.to_s] = canonical
            evidence("status_mappings.#{status}", from_text ? 'description' : 'heuristic', from_text ? 'medium' : 'high', field['pointer'], "Payment status #{status} maps to #{canonical}.")
            diagnostic('status_inferred', field['pointer'], "Status #{status} meaning extracted from text.", 'Confirm status_mappings in overrides.', 'warning') if from_text
          else
            code = from_text == false ? 'status_conflict' : 'status_unmapped'
            message = from_text == false ? "Description of status #{status.inspect} is negated or ambiguous." : "Unknown payment status #{status.inspect}."
            diagnostic(code, field['pointer'], message, "Set status_mappings.#{status} in overrides.", 'error', { 'status' => status.to_s })
          end
        end
      end
    end

    # смотрим все успешные ответы чтобы второй 2xx не спрятал другой смысл статуса
    def response_status_fields(operation)
      fields = operation.fetch('responses', {}).flat_map do |code, response|
        next [] unless code.match?(/\A2(?:\d\d|XX)\z/i)
        pointer = "#{operation['pointer']}/responses/#{code}/content"
        media = select_media(response['content'], pointer)
        flatten(media['schema'], "#{pointer}/#{escape(json_media_key(response['content'] || {}))}/schema")
      end
      fields = operation['response_fields'] if fields.empty?
      fields.select { |field| operation['response_mappings']['status'] == field['path'] }
    end

    # ошибки храним по методам потому что один http-код может иметь разный смысл
    def extract_errors(operations)
      operations.each_with_object({}) do |operation, result|
        operation['error_mappings'] = {}
        operation['responses'].each do |code, response|
          next unless code.to_s.match?(/\A[45]\d\d\z/)
          from_text = @text_rules.error_meaning(response['description'])
          canonical = from_text || HTTP_ERRORS.fetch(code.to_s, 'provider_error')
          operation['error_mappings'][code.to_s] = canonical
          result[code.to_s] ||= canonical
          evidence("#{operation['id']}.error_mappings.#{code}", from_text ? 'description' : 'heuristic', from_text ? 'medium' : 'high', "#{operation['pointer']}/responses/#{code}", "HTTP #{code} maps to #{canonical}.")
        end
      end
    end

    def evidence(subject, source, confidence, pointer, message)
      item = { 'subject' => subject, 'source' => source, 'confidence' => confidence, 'pointer' => pointer, 'message' => message }
      @provenance << item unless @provenance.include?(item)
    end

    def diagnostic(code, pointer, message, action, severity = 'error', details = {})
      item = { 'severity' => severity, 'code' => code, 'pointer' => pointer, 'message' => message, 'action' => action }.merge(details)
      @diagnostics << item unless @diagnostics.include?(item)
    end

    def escape(value)
      value.to_s.gsub('~', '~0').gsub('/', '~1')
    end
  end
end
