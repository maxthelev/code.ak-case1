# frozen_string_literal: true

require 'yaml'
require 'json'

module Integrator
  class Overrides
    ROLES = %w[create status cancel webhook balance unknown].freeze
    CANONICAL = %w[amount currency external_id provider_operation_id status recipient.type recipient.phone recipient.bank_code recipient.bank_name recipient.card_number error.code error.message event payout_id created_at completed_at].freeze
    TOP_KEYS = %w[operations field_mappings response_mappings amount required_if status_mappings error_mappings signature auth idempotency request_methods].freeze

    def initialize(path)
      @path = path
    end

    # накладываем ручные уточнения а после смены полей пересчитываем зависимые правила
    def apply(ir)
      return ir unless @path

      raise Error, 'Overrides file exceeds 1 MB' if File.size(@path) > 1_048_576
      data = SpecLoader.parse_yaml(File.read(@path, encoding: 'UTF-8'))
      SpecLoader.json_value!(data)
      keys!(data, TOP_KEYS, 'overrides')
      @ir = JSON.parse(JSON.generate(ir))
      structural = %w[operations field_mappings response_mappings]
      data.each { |key, value| merge_entry(key, value) if structural.include?(key) }
      Analyzer.new({}, provider: @ir['provider']).recompute_semantics(@ir) if data.keys.any? { |key| structural.include?(key) }
      data.each { |key, value| merge_entry(key, value) unless structural.include?(key) }
      @ir
    rescue Psych::Exception, SystemCallError, JSON::GeneratorError => e
      raise Error, "Cannot load overrides #{@path}: #{e.message}"
    end

    private

    # опечатку в overrides считаем ошибкой чтобы настройка не потерялась молча
    def keys!(value, allowed, label)
      raise Error, "#{label} must be a mapping" unless value.is_a?(Hash)
      unknown = value.keys - allowed
      raise Error, "Unknown #{label} keys: #{unknown.join(', ')}" unless unknown.empty?
    end

    def strings!(value, label)
      raise Error, "#{label} must map strings to strings" unless value.is_a?(Hash) && value.all? { |k, v| k.is_a?(String) && v.is_a?(String) && !k.empty? && !v.empty? }
    end

    def choice!(value, choices, label)
      raise Error, "#{label} must be one of #{choices.join(', ')}" unless choices.include?(value)
    end

    def operation(id)
      @ir.fetch('operations').find { |op| op['id'] == id } || raise(Error, "Unknown operation in overrides: #{id}")
    end

    def record(subject)
      @ir['provenance'] ||= []
      @ir['provenance'] << {'subject' => subject, 'source' => 'override', 'confidence' => 'explicit', 'pointer' => "overrides#/#{subject}", 'message' => 'Explicit integration configuration'}
    end

    # каждый раздел проверяем отдельно и отмечаем что значение выбрали вручную
    def merge_entry(key, value)
      case key
      when 'operations'
        strings!(value, key)
        value.each do |id, role|
          choice!(role, ROLES, "operations.#{id}")
          operation(id).merge!('role' => role, 'confidence' => 'explicit')
        end
      when 'field_mappings', 'response_mappings'
        raise Error, "#{key} must be a mapping" unless value.is_a?(Hash)
        value.each do |id, mappings|
          strings!(mappings, "#{key}.#{id}")
          op = operation(id)
          mappings.each do |left, right|
            canonical, target = key == 'field_mappings' ? [right, left] : [left, right]
            choice!(canonical, CANONICAL, "#{key}.#{id}.#{left}")
            fields = key == 'field_mappings' ? op.fetch('fields', []) : op.fetch('response_fields', [])
            paths = fields.map { |f| f['path'] }
            paths += op.fetch('parameters', []).map { |p| p['name'] } if key == 'field_mappings'
            raise Error, "Unknown target field #{id}.#{target}" unless paths.include?(target)
            record("#{key}.#{id}.#{left}")
          end
          op[key] = op.fetch(key, {}).merge(mappings)
        end
      when 'amount'
        keys!(value, %w[unit factor], key)
        choice!(value['unit'], %w[major minor], 'amount.unit') if value.key?('unit')
        factor = value['factor']
        if value.key?('factor') && !(factor.is_a?(Numeric) && factor.finite? && factor.positive?)
          raise Error, 'amount.factor must be a positive finite number'
        end
        merged = @ir.fetch('amount', {}).merge(value)
        raise Error, 'Major units require factor 1' if merged['unit'] == 'major' && merged['factor'] != 1
        @ir[key] = merged.merge('source' => 'override', 'confidence' => 'explicit')
      when 'signature'
        keys!(value, %w[algorithm header signed_data encoding], key)
        choice!(value['algorithm'], %w[HMAC-SHA256 none], 'signature.algorithm') if value.key?('algorithm')
        choice!(value['signed_data'], %w[raw_body], 'signature.signed_data') if value.key?('signed_data')
        choice!(value['encoding'], %w[hex base64], 'signature.encoding') if value.key?('encoding')
        if value.key?('header') && !(value['header'].is_a?(String) && value['header'].match?(/\A[A-Za-z0-9!#$%&'*+.^_`|~-]+\z/))
          raise Error, 'signature.header must be an HTTP header name'
        end
        @ir[key] = @ir.fetch(key, {}).merge(value).merge('source' => 'override', 'confidence' => 'explicit')
      when 'required_if'
        raise Error, 'required_if must be an array' unless value.is_a?(Array)
        value.each do |rule|
          keys!(rule, %w[field when], key)
          keys!(rule['when'], %w[field value], 'required_if.when')
          fields = @ir['operations'].flat_map { |op| op.fetch('fields', []).map { |f| f['path'] } }
          unless fields.include?(rule['field']) && fields.include?(rule['when']['field']) && rule['when'].key?('value') && [String, Numeric, TrueClass, FalseClass].any? { |type| rule['when']['value'].is_a?(type) }
            raise Error, 'required_if requires existing field, condition field and scalar value'
          end
        end
        previous = @ir.fetch(key, []).reject { |rule| value.any? { |new_rule| new_rule['field'] == rule['field'] && new_rule['when'] == rule['when'] } }
        @ir[key] = previous + value.map { |rule| rule.merge('source' => 'override', 'confidence' => 'explicit') }
      when 'request_methods'
        raise Error, 'request_methods must be a mapping' unless value.is_a?(Hash)
        targets = value.to_h do |name, target|
          raise Error, 'request_method name must be a nonempty string' unless name.is_a?(String) && !name.empty?
          if target.is_a?(String) && (ROLES - %w[unknown webhook]).include?(target)
            resolved = target
          else
            keys!(target, %w[operationId], "request_methods.#{name}") if target.is_a?(Hash)
            id = target.is_a?(Hash) ? target['operationId'] : target
            raise Error, 'operationId must be a nonempty string' unless id.is_a?(String) && !id.empty?
            choice!(operation(id)['role'], ROLES - %w[unknown webhook], "request_methods.#{name} role")
            resolved = {'operationId' => id}
          end
          record("request_methods.#{name}")
          [name, resolved]
        end
        @ir[key] = @ir.fetch(key, {}).merge(targets)
      when 'status_mappings', 'error_mappings'
        strings!(value, key)
        value.each do |source, target|
          choice!(target, %w[in_progress approved rejected], key) if key == 'status_mappings'
          raise Error, 'HTTP error mapping keys must be 400..599 or default' if key == 'error_mappings' && !source.match?(/\A(?:[45]\d\d|default)\z/)
          record("#{key}.#{source}")
        end
        @ir[key] = @ir.fetch(key, {}).merge(value)
        if key == 'error_mappings'
          @ir.fetch('operations').each do |op|
            op['error_mappings'] = op.fetch('error_mappings', {}).merge(value)
          end
        end
      when 'auth'
        raise Error, 'auth must be a mapping' unless value.is_a?(Hash)
        value.each do |name, config|
          raise Error, "Unknown auth scheme #{name}" unless @ir.fetch('auth_schemes', {}).key?(name)
          keys!(config, %w[credential], "auth.#{name}")
          raise Error, 'auth credential must be an identifier' unless config['credential'].is_a?(String) && config['credential'].match?(/\A[a-z][a-z0-9_]*\z/)
          @ir['auth_schemes'][name]['credential'] = config['credential']
        end
        @ir[key] = @ir.fetch(key, {}).merge(value)
      when 'idempotency'
        raise Error, 'idempotency must be a mapping' unless value.is_a?(Hash)
        value.each do |id, config|
          keys!(config, %w[name in], "idempotency.#{id}")
          choice!(config['in'], %w[header query], "idempotency.#{id}.in")
          raise Error, 'Idempotency name must be a token' unless config['name'].is_a?(String) && config['name'].match?(/\A[A-Za-z0-9_-]+\z/)
          operation(id)['idempotency'] = config
        end
      end
      record(key)
    end
  end
end
