# frozen_string_literal: true

module Integrator
  class RuntimeConfigBuilder
    OPERATION_KEYS = %w[id role method path security field_mappings response_mappings request_media_type response_media_type events].freeze
    SCHEMA_KEYS = %w[type required enum default nullable format pattern minLength maxLength minimum maximum exclusiveMinimum exclusiveMaximum multipleOf minItems maxItems uniqueItems].freeze

    def initialize(ir)
      @ir = ir
    end

    # из полного ir оставляем только данные которые читает готовый сервис
    def build
      config = @ir.slice('provider', 'request_methods', 'status_mappings')
      config['servers'] = servers(@ir.fetch('servers', []))
      config['operations'] = @ir.fetch('operations', []).map { |operation| operation_config(operation) }
      config['auth_schemes'] = @ir.fetch('auth_schemes', {}).transform_values { |scheme| scheme.slice('type', 'scheme', 'in', 'name', 'credential') }
      config['amount'] = @ir.fetch('amount', {}).slice('unit', 'factor')
      config['signature'] = @ir.fetch('signature', {}).slice('algorithm', 'header', 'signed_data', 'encoding')
      config['required_if'] = @ir.fetch('required_if', []).map { |rule| {'field' => rule['field'], 'when' => rule.fetch('when').slice('field', 'value')} }
      config['diagnostics'] = @ir.fetch('diagnostics', []).select { |item| %w[error critical].include?(item['severity']) }.map { |item| item.slice('severity', 'code', 'message') }
      config
    end

    private

    # для каждого метода переносим запрос параметры и схемы успешных ответов
    def operation_config(operation)
      config = operation.slice(*OPERATION_KEYS)
      config['servers'] = servers(operation.fetch('servers', []))
      config['parameters'] = operation.fetch('parameters', []).map do |parameter|
        parameter.slice('name', 'in', 'required').merge('schema' => schema(parameter.fetch('schema', {})))
      end
      config['request'] = {'schema' => schema(operation['request']['schema'])} if operation.dig('request', 'schema')
      config['idempotency'] = operation['idempotency'].slice('name', 'in') if operation['idempotency']
      config['responses'] = operation.fetch('responses', {}).select { |code, _| code.match?(/\A2(?:\d\d|XX)\z/i) || code == 'default' }.transform_values do |response|
        content = response.fetch('content', {})
        raise Error, 'Response content must be an object' unless content.is_a?(Hash)
        media = content.transform_keys(&:downcase).select { |type, _| type == 'application/json' || type.end_with?('+json') }
        {'content' => media.transform_values { |value| {'schema' => schema(value.fetch('schema', {}))} }}
      end.transform_keys { |code| code == 'default' ? code : code.upcase }
      config
    end

    def servers(values)
      values.map { |server| server.slice('url') }
    end

    # убираем описания схемы но не трогаем содержимое defaults и имена свойств
    def schema(value)
      compact = value.slice(*SCHEMA_KEYS)
      compact['properties'] = value['properties'].transform_values { |child| schema(child) } if value['properties']
      compact['items'] = schema(value['items']) if value['items']
      compact
    end
  end
end
