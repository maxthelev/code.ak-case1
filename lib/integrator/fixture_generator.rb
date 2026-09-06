# frozen_string_literal: true

require 'json'
require 'openssl'
require 'base64'

module Integrator
  class FixtureGenerator
    TEST_SECRET = 'fake-callback-secret-for-tests-only'.freeze
    MAX_FIXTURE_NODES = 10_000
    MAX_FIXTURE_BYTES = 20 * 1024 * 1024

    def initialize(ir)
      @ir = ir
    end

    # для каждого метода собираем примеры и отмечаем где пришлось подобрать значения
    def generate
      @warnings = []
      @sources = {}
      @fixture_nodes = 0
      @fixture_bytes = 0
      fixtures = {}
      @ir.fetch('operations', []).each do |operation|
        if operation['role'] == 'webhook'
          callback_fixtures(operation, fixtures)
          next
        end
        key = { 'create' => 'create_request', 'status' => 'fetch_status' }.fetch(operation['role'], operation['role'])
        key = operation['id'] if key.nil? || key == 'unknown' || fixtures.key?(key)
        fixture = {}
        if operation['request'] && !operation['request'].empty?
          fixture['request'] = media_value(operation['request'], "#{operation['id']}.request")
        end
        operation.fetch('responses', {}).each do |status, response|
          media = json_media(response['content'])
          location = "#{operation['id']}.response.#{status}"
          mappings = operation.fetch('response_mappings', {})
          selection = if status.to_s.match?(/\A2(?:\d\d|XX)\z/i)
                        { 'paths' => mappings.reject { |key, _| key.start_with?('error.') || key == 'error' }.values,
                          'errors' => mappings.filter_map do |key, target|
                            next unless key.start_with?('error.') || key == 'error'

                            parts = target.split('.')
                            parts.first([parts.length - key.count('.'), 1].max).join('.')
                          end }
                      end
          value = media ? media_value(media, location, selection) : nil
          align_error_example(value, media, status, operation) if @sources[location] == 'schema fallback'
          fixture["response_#{status}"] = value
        end
        fixtures[key] = fixture
      end
      vector = signature_vector(fixtures.dig('callback', 'payload'))
      fixtures['signature_test_vector'] = vector if vector
      fixtures['_meta'] = {
        'description' => 'Примеры для локальных тестов. Значения, подобранные по схеме, нужно проверить.',
        'sources' => @sources, 'warnings' => @warnings
      }
      fixtures
    end

    private

    def json_media(content)
      return unless content.is_a?(Hash)

      content.find { |name, _| name.downcase == 'application/json' }&.last ||
        content.find { |name, _| name.match?(%r{\Aapplication/[^;]+\+json\z}i) }&.last
    end

    # подставляем смысл ошибки только в fallback а явные примеры не меняем
    def align_error_example(value, media, status, operation)
      errors = operation.fetch('error_mappings', {})
      global_errors = @ir.fetch('error_mappings', {})
      mapped = errors[status.to_s] || errors['default'] || global_errors[status.to_s] || global_errors['default']
      payload_schema = media.fetch('schema', {})
      error_schema = payload_schema.dig('properties', 'error') || {}
      schema = error_schema.dig('properties', 'code') || {}
      return if [payload_schema, error_schema, schema].any? { |node| explicit_value?(node) }
      return unless mapped && schema.fetch('enum', []).include?(mapped)
      return unless value.is_a?(Hash) && value['error'].is_a?(Hash)

      value['error']['code'] = mapped
    end

    # пример из openapi важнее значений которые можно подобрать по схеме
    def media_value(media, location, selection = nil)
      if media.key?('example')
        @sources[location] = 'OpenAPI example'
        return copy(media['example'])
      end
      example = media.fetch('examples', {}).values.find { |item| item.is_a?(Hash) && item.key?('value') }
      if example
        @sources[location] = 'OpenAPI examples'
        return copy(example['value'])
      end
      @sources[location] = 'schema fallback'
      schema = media.fetch('schema', {})
      value = schema_value(schema, location, selection)
      filter_conditional_fields(value, schema)
      value
    end

    # если примера нет собираем небольшой ответ из нужных полей и ограничений
    def schema_value(schema, location, selection = nil, path = '')
      return copy(schema['example']) if schema.key?('example')
      return copy(schema['default']) if schema.key?('default')
      return copy(schema['const']) if schema.key?('const')
      return copy(schema['enum'].first) if schema['enum']&.any?

      alternative = schema['oneOf'] || schema['anyOf']
      if alternative&.any?
        @warnings << "#{location}: выбран первый вариант схемы; проверьте его по discriminator."
        return schema_value(alternative.first, location, selection, path)
      end
      consume_node!
      type = schema['type'] || ('object' if schema['properties'])
      type = type.find { |item| item != 'null' } if type.is_a?(Array)
      value = case type
      when 'object'
        schema.fetch('properties', {}).each_with_object({}) do |(name, field), result|
          field_path = [path, name].reject(&:empty?).join('.')
          next if selection && !include_response_field?(schema, name, field, field_path, selection)

          result[name] = schema_value(field, "#{location}.#{name}", selection, field_path)
        end
      when 'array'
        count = [schema.fetch('minItems', 1), 100].min
        @warnings << "#{location}: пример массива ограничен 100 элементами." if schema.fetch('minItems', 0) > 100
        Array.new(count) { schema_value(schema.fetch('items', {}), "#{location}[]", selection, path) }
      when 'integer', 'number'
        number_value(schema, type)
      when 'boolean' then true
      when 'null' then nil
      else string_value(schema, location)
      end
      consume_bytes!(value)
      value
    end

    def explicit_value?(schema)
      %w[example default const].any? { |key| schema.key?(key) }
    end

    def nested_explicit_value?(schema)
      explicit_value?(schema) || schema.fetch('properties', {}).values.any? { |field| nested_explicit_value?(field) }
    end

    # в успешный ответ не добавляем все необязательные поля и объекты ошибок
    def include_response_field?(parent, name, field, path, selection)
      return true if parent.fetch('required', []).include?(name) || explicit_value?(field)
      return false if name == 'error' || selection['errors'].include?(path)

      nested_explicit_value?(field) || selection['paths'].any? { |target| target == path || target.start_with?("#{path}.") }
    end

    # оставляем реквизиты выбранного типа а не заполняем сразу все варианты
    def filter_conditional_fields(value, schema)
      @ir.fetch('required_if', []).group_by { |rule| rule['field'] }.each do |path, rules|
        conditions = rules.map do |rule|
          actual = rule.dig('when', 'field').to_s.split('.').reduce(value) { |node, name| node.is_a?(Hash) ? node[name] : nil }
          actual.nil? ? nil : actual == rule.dig('when', 'value')
        end
        next unless conditions.all?(false)

        parts = path.split('.')
        node = value
        field_schema = schema
        parts.each_with_index do |name, index|
          break unless node.is_a?(Hash)
          break if explicit_value?(field_schema)

          if index == parts.length - 1
            node.delete(name) unless field_schema.fetch('required', []).include?(name)
          else
            node = node[name]
            field_schema = field_schema.dig('properties', name) || {}
          end
        end
      end
    end

    # подбираем число с учётом типа нижней границы и шага
    def number_value(schema, type)
      value = schema.fetch('minimum', 1)
      exclusive = schema['exclusiveMinimum']
      value = exclusive if exclusive.is_a?(Numeric)
      value += (type == 'integer' ? 1 : 0.01) if exclusive && exclusive != false
      value = [value, schema['maximum']].min if schema['maximum']
      type == 'integer' ? value.ceil : value
    end

    # используем известный формат или простой шаблон а нерешённые случаи отмечаем
    def string_value(schema, location)
      formats = {
        'date-time' => '2026-01-01T00:00:00Z', 'date' => '2026-01-01',
        'uuid' => '00000000-0000-4000-8000-000000000001',
        'email' => 'fixture@example.invalid', 'uri' => 'https://fixture.example.invalid'
      }
      value = formats.fetch(schema['format'], 'fixture')
      if schema['pattern']
        value = pattern_value(schema['pattern'])
        unless value
          @warnings << "#{location}: не удалось подобрать значение для pattern #{schema['pattern'].inspect}; укажите его вручную."
          value = 'REPLACE_PATTERN_VALUE'
        end
      end
      minimum = [schema.fetch('minLength', 0), 1024].min
      value = value.ljust(minimum, 'x')
      value = value[0, schema['maxLength']] if schema['maxLength']
      value
    end

    # поддерживаем несколько простых шаблонов без попытки генерировать любой regexp
    def pattern_value(pattern)
      normalized = pattern.gsub('\\\\d', '\\d')
      match = normalized.match(/\A\^([A-Za-z0-9]*)(\\d|\[0-9\]|\[A-Z\]|\[a-z\])\{(\d+)\}\$\z/)
      return unless match && match[3].to_i <= 100

      character = { '\\d' => '1', '[0-9]' => '1', '[A-Z]' => 'A', '[a-z]' => 'a' }.fetch(match[2])
      match[1] + character * match[3].to_i
    end

    # сохраняем примеры успешного и неуспешного webhook если они есть в спеке
    def callback_fixtures(operation, fixtures)
      media = operation.fetch('request', {})
      examples = media.fetch('examples', {}).filter_map do |name, example|
        [name, copy(example['value'])] if example.is_a?(Hash) && example.key?('value')
      end
      examples = [['default', media_value(media, "#{operation['id']}.request")]] if examples.empty?
      examples.sort_by! { |_, payload| callback_status(operation, payload) == 'approved' ? 0 : 1 }
      examples.each do |name, payload|
        status = callback_status(operation, payload)
        key = status == 'rejected' ? 'callback_failed' : 'callback'
        key = "callback_#{operation['id']}_#{name}" if fixtures.key?(key)
        @sources[key] = media.fetch('examples', {}).empty? ? 'schema/example fallback' : 'OpenAPI examples'
        fixtures[key] = { 'payload' => payload, 'expected_operation_status' => status }
        @warnings << "#{key}: ожидаемый статус не определён; уточните сопоставления статусов и полей." unless status
      end
    end

    def callback_status(operation, payload)
      target = operation.fetch('field_mappings', {}).key('status') || operation.fetch('response_mappings', {})['status']
      value = target.to_s.split('.').reduce(payload) { |node, field| node.is_a?(Hash) ? node[field] : nil }
      @ir.fetch('status_mappings', {})[value]
    end

    # делаем локальный пример подписи с заведомо тестовым секретом
    def signature_vector(payload)
      signature = @ir.fetch('signature', {}) || {}
      return unless payload && signature['algorithm'].to_s.upcase == 'HMAC-SHA256' && signature['signed_data'] == 'raw_body'
      return unless %w[hex base64].include?(signature['encoding']) && signature['header']

      raw_body = JSON.generate(payload)
      digest = OpenSSL::HMAC.digest('SHA256', TEST_SECRET, raw_body)
      encoded = signature['encoding'] == 'hex' ? digest.unpack1('H*') : Base64.strict_encode64(digest)
      {
        'description' => 'Тестовый секрет. Не используйте его для реальной авторизации.',
        'secret' => TEST_SECRET, 'raw_body' => raw_body,
        'headers' => { signature['header'] => encoded }, 'encoding' => signature['encoding']
      }
    end

    # копируем примеры с общим лимитом чтобы повторения не раздули итоговый файл
    def copy(value, depth = 0)
      raise Error, 'Fixture nesting exceeds 128 levels' if depth > 128
      consume_node!
      consume_bytes!(value)
      case value
      when Hash then value.transform_values { |child| copy(child, depth + 1) }
      when Array then value.map { |child| copy(child, depth + 1) }
      when String then value.dup
      else value
      end
    end

    def consume_node!
      @fixture_nodes += 1
      raise Error, "Fixture generation exceeds #{MAX_FIXTURE_NODES} nodes" if @fixture_nodes > MAX_FIXTURE_NODES
    end

    # считаем и строки и контейнеры даже если в примере мало узлов
    def consume_bytes!(value)
      @fixture_bytes += case value
                        when Hash then 2 + value.keys.sum { |key| JSON.generate(key).bytesize + 2 }
                        when Array then value.length + 2
                        else JSON.generate(value).bytesize
                        end
      raise Error, "Fixture generation exceeds #{MAX_FIXTURE_BYTES} bytes" if @fixture_bytes > MAX_FIXTURE_BYTES
    end
  end
end
