# frozen_string_literal: true

module Integrator
  class Validator
    def initialize(ir)
      @ir = ir
    end

    # перед генерацией проверяем что критичные вопросы решены и убираем старые замечания
    def validate
      @ir['diagnostics'] ||= []
      @ir['diagnostics'].reject! { |d| d['stage'] == 'validation' || resolved_diagnostic?(d) }
      confirm_inferences
      @ir.fetch('operations', []).each { |op| validate_operation(op) }
      roles = @ir.fetch('operations', []).group_by { |op| op['role'] }
      selected_ids = @ir.fetch('request_methods', {}).values.grep(Hash).map { |target| target['operationId'] }
      roles.each do |role, ops|
        next if ops.size < 2 || role == 'unknown'
        next if role != 'webhook' && ops.all? { |op| selected_ids.include?(op['id']) }
        error('duplicate_role', '#/operations', "Several operations map to #{role}: #{ops.map { |op| op['id'] }.join(', ')}", 'Select each operationId explicitly in request_methods or keep one operation per role')
      end
      validate_signature if roles.key?('webhook')
      @ir['diagnostics'].none? { |d| %w[error critical].include?(d['severity']) }
    end

    private

    # снимаем только те замечания для которых уже появилось нужное уточнение
    def resolved_diagnostic?(diagnostic)
      operations = @ir.fetch('operations', [])
      case diagnostic['code']
      when 'operation_ambiguous'
        operations.any? { |op| op['pointer'] == diagnostic['pointer'] && op['role'] != 'unknown' && op['confidence'] == 'explicit' }
      when 'field_unmapped'
        operations.any? do |op|
          op.fetch('fields', []).any? { |field| field['pointer'] == diagnostic['pointer'] && field_available?(field, op) }
        end
      when 'field_ambiguous'
        resolved_field_ambiguity?(diagnostic, operations)
      when 'status_conflict'
        diagnostic['status'] && explicit_mapping?("status_mappings.#{diagnostic['status']}")
      when 'amount_unresolved'
        amount = @ir.fetch('amount', {})
        %w[major minor].include?(amount['unit']) && amount['factor'].is_a?(Numeric) && amount['factor'].positive?
      when 'status_unmapped'
        return true if diagnostic['status'] && @ir.fetch('status_mappings', {}).key?(diagnostic['status'])
        fields = operations.flat_map { |op| op.fetch('fields', []) + op.fetch('response_fields', []) }.select { |field| field['pointer'] == diagnostic['pointer'] }
        !fields.empty? && fields.all? { |field| Array(field.dig('schema', 'enum')).all? { |s| @ir.fetch('status_mappings', {}).key?(s) } }
      else
        false
      end
    end

    # ручной выбор поля должен действительно убрать конфликт а не просто добавить ещё одно
    def resolved_field_ambiguity?(diagnostic, operations)
      operations.any? do |op|
        response_field = op.fetch('response_fields', []).find { |field| field['pointer'] == diagnostic['pointer'] }
        if response_field
          canonical = FieldMapper.new.canonical(response_field, response: true)
          explicit_mapping?("response_mappings.#{op['id']}.#{canonical}")
        else
          request_field = op.fetch('fields', []).find { |field| field['pointer'] == diagnostic['pointer'] }
          next false unless request_field
          canonical = FieldMapper.new.canonical(request_field, response: op['role'] == 'webhook')
          body_paths = op.fetch('fields', []).map { |field| field['path'] }
          mappings = op.fetch('field_mappings', {}).select { |path, _| body_paths.include?(path) }
          mappings.values.count(canonical) <= 1 && mappings.keys.any? { |path| explicit_mapping?("field_mappings.#{op['id']}.#{path}") }
        end
      end
    end

    def explicit_mapping?(subject)
      @ir.fetch('provenance', []).any? { |item| item['source'] == 'override' && item['subject'] == subject }
    end

    # поле можно собрать из маппинга default или единственного значения enum
    def field_available?(field, operation)
      return false unless field
      return true if operation.fetch('field_mappings', {}).key?(field['path'])
      schema = field.fetch('schema', {})
      !schema['default'].nil? || (schema.fetch('enum', []).size == 1 && !schema['enum'].first.nil?)
    end

    # подтверждённые через overrides догадки больше не показываем как предупреждения
    def confirm_inferences
      @ir['diagnostics'].each do |diagnostic|
        confirmed = case diagnostic['code']
                    when 'amount_inferred' then @ir.dig('amount', 'source') == 'override'
                    when 'signature_inferred' then @ir.dig('signature', 'source') == 'override'
                    when 'conditional_inferred'
                      operation = @ir.fetch('operations', []).find { |op| op['pointer'] == diagnostic['pointer'] || op.fetch('fields', []).any? { |field| field['pointer'] == diagnostic['pointer'] } }
                      next unless operation
                      fields = operation.fetch('fields', []).select { |field| operation['pointer'] == diagnostic['pointer'] || field['pointer'] == diagnostic['pointer'] }.map { |field| field['path'] }
                      rules = @ir.fetch('required_if', []).select { |rule| fields.include?(rule['field']) }
                      !rules.empty? && rules.all? { |rule| rule['source'] == 'override' }
                    end
        next unless confirmed
        diagnostic.merge!('severity' => 'info', 'resolved' => true, 'message' => "#{diagnostic['code'].delete_suffix('_inferred')} confirmed by explicit overrides.", 'action' => 'See override provenance for the confirmed configuration.')
      end
    end

    def error(code, pointer, message, action)
      @ir['diagnostics'] << {'severity' => 'error', 'code' => code, 'pointer' => pointer, 'message' => message, 'action' => action, 'stage' => 'validation'}
    end

    # проверяем что для выбранной роли есть рабочий запрос ответ и нужные настройки
    def validate_operation(op)
      pointer = op['pointer'] || "#/operations/#{op['id']}"
      path = op['path']
      unless path.is_a?(String) && path.start_with?('/') && !path.match?(/[\s?#\\]/)
        error('invalid_operation_path', pointer, 'Operation path must be an absolute URL path without query, fragment or whitespace', 'Put query values in declared parameters')
      end
      unless %w[get post put patch delete].include?(op['method'])
        error('unsupported_http_method', pointer, "HTTP method #{op['method']} is not supported by the generated client", 'Use get/post/put/patch/delete or implement a client adapter')
      end
      if op['role'] == 'unknown'
        error('unresolved_operation', pointer, "Unknown semantic role for #{op['id']}", "Set operations.#{op['id']} override")
        return
      end
      mappings = op.fetch('field_mappings', {})
      validate_message_shapes(op, pointer)
      validate_response_mappings(op, pointer)
      if op['role'] == 'create'
        validate_conditions(op, pointer)
        op.fetch('fields', []).each do |field|
          schema = field.fetch('schema', {})
          next unless field['required'] && !mappings.key?(field['path']) && !schema.key?('default') && schema.fetch('enum', []).length != 1
          error('unmapped_field', field['pointer'] || pointer, "Required field #{field['path']} has no canonical mapping", "Set field_mappings.#{op['id']}.#{field['path']}")
        end
        if mappings.value?('amount')
          amount = @ir.fetch('amount', {})
          unless %w[major minor].include?(amount['unit']) && amount['factor'].is_a?(Numeric) && amount['factor'].positive?
            error('unresolved_amount', pointer, 'Amount unit or conversion factor is unresolved', 'Set amount.unit and amount.factor overrides')
          end
        end
      end
      if %w[create status cancel].include?(op['role'])
        %w[status provider_operation_id].each do |canonical|
          next if op.fetch('response_mappings', {}).key?(canonical)
          error('missing_response_mapping', pointer, "#{op['id']} needs #{canonical} response mapping", "Set response_mappings.#{op['id']}.#{canonical}")
        end
      end
      if op['role'] == 'webhook'
        %w[status provider_operation_id].each do |canonical|
          next if mappings.value?(canonical)
          error('missing_callback_mapping', pointer, "Callback needs #{canonical} mapping", "Set field_mappings.#{op['id']}")
        end
      end
      validate_statuses(op, pointer)
      unless op['role'] == 'webhook'
        validate_auth(op, pointer)
        validate_parameters(op, pointer)
      end
    end

    # runtime собирает запрос и читает успешный ответ как json-объект
    def validate_message_shapes(op, pointer)
      schemas = [[op.dig('request', 'schema'), "#{pointer}/requestBody"]]
      op.fetch('responses', {}).each do |code, response|
        next unless code.match?(/\A2(?:\d\d|XX)\z/i) || code == 'default'
        response.fetch('content', {}).each do |name, media|
          next unless name.to_s.downcase == 'application/json' || name.to_s.match?(%r{\Aapplication/[^;]+\+json\z}i)
          next unless media.is_a?(Hash)

          schemas << [media['schema'], "#{pointer}/responses/#{code}"]
        end
      end
      schemas.each do |schema, location|
        next unless schema.is_a?(Hash) && schema.key?('type') && schema['type'] != 'object'
        error('unsupported_message_shape', location, 'Generated runtime requires a JSON object at the message root', 'Use an object wrapper or implement a message adapter before generation')
      end
    end

    # одно поле ответа нельзя одновременно использовать как разные по смыслу значения
    def validate_response_mappings(op, pointer)
      op.fetch('response_mappings', {}).group_by { |_, source| source }.each do |source, pairs|
        next unless pairs.size > 1
        error('response_mapping_collision', pointer, "Response field #{source} is assigned to incompatible canonical fields: #{pairs.map(&:first).join(', ')}", "Use distinct response_mappings.#{op['id']} sources")
      end
    end

    # обе стороны required_if должны существовать и собираться из operation
    def validate_conditions(op, pointer)
      fields = op.fetch('fields', [])
      @ir.fetch('required_if', []).each do |rule|
        target = fields.find { |field| field['path'] == rule['field'] }
        next unless target
        condition = fields.find { |field| field['path'] == rule.dig('when', 'field') }
        [target, condition].each do |field|
          next if field_available?(field, op)
          name = field ? field['path'] : rule.dig('when', 'field')
          error('unmapped_conditional_field', field&.fetch('pointer', nil) || pointer, "Conditional requirement field #{name} cannot be built for #{op['id']}", "Set field_mappings.#{op['id']}.#{name} or a schema default")
        end
      end
    end

    # обязательные параметры должны приходить из полей auth defaults или idempotency
    def validate_parameters(op, pointer)
      automatic = Array(op['security']).flat_map(&:keys).filter_map { |name| @ir.fetch('auth_schemes', {})[name] }.map { |scheme| [scheme['in'], scheme['name']] }
      automatic << [op.dig('idempotency', 'in'), op.dig('idempotency', 'name')]
      op.fetch('parameters', []).each do |parameter|
        unless %w[path query header].include?(parameter['in'])
          error('unsupported_parameter_location', pointer, 'Parameter location is not supported by the generated client', 'Use path, query or header parameters')
        end
        next unless parameter['required']
        next if automatic.include?([parameter['in'], parameter['name']])
        next if op.fetch('field_mappings', {}).key?(parameter['name'])
        schema = parameter.fetch('schema', {})
        next if schema.key?('default') || schema.fetch('enum', []).length == 1
        error('unmapped_parameter', pointer, "Required #{parameter['in']} parameter #{parameter['name']} has no mapping", "Set field_mappings.#{op['id']}.#{parameter['name']}")
      end
    end

    # без enum используем общую карту статусов но пустую карту не принимаем
    def validate_statuses(op, pointer)
      path = op['role'] == 'webhook' ? op.fetch('field_mappings', {}).key('status') : op.fetch('response_mappings', {})['status']
      fields = op['role'] == 'webhook' ? op.fetch('fields', []) : op.fetch('response_fields', [])
      field = fields.find { |f| f['path'] == path }
      if path && Array(field&.dig('schema', 'enum')).empty? && @ir.fetch('status_mappings', {}).empty?
        error('unresolved_status_values', pointer, 'Status field has no known values and the provider status map is empty', 'Set explicit status_mappings or supply a reliable status enum in another endpoint')
      end
      Array(field&.dig('schema', 'enum')).each do |status|
        next if @ir.fetch('status_mappings', {}).key?(status)
        error('unmapped_status', field['pointer'] || pointer, "Unknown provider status #{status}", "Set status_mappings.#{status} override")
      end
    end

    # для запроса должна остаться хотя бы одна поддерживаемая схема авторизации
    def validate_auth(op, pointer)
      alternatives = Array(op['security'])
      usable_alternative = alternatives.any? { |alternative| alternative.keys.all? { |name| supported_auth?(@ir.fetch('auth_schemes', {})[name]) } }
      alternatives.each do |alternative|
        alternative.each_key do |name|
          scheme = @ir.fetch('auth_schemes', {})[name]
          if !scheme
            error('missing_auth', pointer, "Undefined security scheme #{name}", 'Define components/securitySchemes')
          elsif !supported_auth?(scheme)
            if usable_alternative
              @ir['diagnostics'] << { 'severity' => 'warning', 'code' => 'unsupported_auth_alternative', 'pointer' => pointer,
                                      'message' => "Unsupported authentication alternative #{name}; a supported alternative is available.",
                                      'action' => 'Provide credentials for a supported security alternative.', 'stage' => 'validation' }
            else
              error('unsupported_auth', pointer, "Unsupported authentication #{name}", 'Use an API key or HTTP bearer/basic scheme; OAuth token acquisition belongs to the host')
            end
          end
        end
      end
    end

    # проверяем не только тип auth но и корректность имени api key
    def supported_auth?(scheme)
      return false unless scheme.is_a?(Hash)
      if scheme['type'] == 'apiKey'
        name = scheme['name']
        return false unless name.is_a?(String) && !name.empty? && !name.match?(/[\r\n]/)
        return false if scheme['in'] == 'header' && !/\A[!#$%&'*+.^_`|~0-9A-Za-z-]+\z/.match?(name)
        %w[header query].include?(scheme['in'])
      else
        scheme['type'] == 'http' && %w[bearer basic].include?(scheme['scheme'].to_s.downcase)
      end
    end

    # для подписанного webhook нужны алгоритм заголовок исходные данные и кодировка
    def validate_signature
      signature = @ir.fetch('signature', {})
      return if signature['algorithm'] == 'none'
      valid = signature['algorithm'].to_s.upcase == 'HMAC-SHA256' && signature['signed_data'] == 'raw_body' && %w[hex base64].include?(signature['encoding']) && !signature['header'].to_s.empty?
      return if valid
      error('unresolved_signature', '#/signature', 'Callback signature algorithm/header/input/encoding is incomplete', 'Set signature {algorithm: HMAC-SHA256, header: ..., signed_data: raw_body, encoding: hex|base64}; explicitly set algorithm: none only for an unsigned contract')
    end
  end
end
