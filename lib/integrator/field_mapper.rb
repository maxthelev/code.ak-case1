# frozen_string_literal: true

module Integrator
  class FieldMapper
    ALIASES = {
      'amount' => %w[amount total_amount payment_amount amount_minor value sum],
      'currency' => %w[currency currency_code ccy],
      'external_id' => %w[external_id merchant_reference merchant_order_id reference client_reference order_id],
      'provider_operation_id' => %w[id payout_id payment_id transfer_id transaction_id operation_id provider_id],
      'status' => %w[status state payment_status transaction_status],
      'event' => %w[event event_type notification_type],
      'created_at' => %w[created_at created_on creation_time],
      'completed_at' => %w[completed_at settled_at paid_at],
      'recipient.phone' => %w[phone phone_number msisdn mobile],
      'recipient.bank_code' => %w[bank_code bic bank_bic routing_number],
      'recipient.bank_name' => %w[bank_name],
      'recipient.card_number' => %w[card_number pan],
      'error.code' => %w[error_code failure_code],
      'error.message' => %w[error_message failure_message]
    }.freeze

    # сопоставляем имя и контекст поля с amount currency status и другими полями хоста
    def canonical(field, response: false)
      path = field['path']
      name = normalize(path.split('.').last)
      return nil if name == 'merchant_id'
      parent = normalize(path.split('.')[-2].to_s)
      if %w[recipient beneficiary destination payee].include?(parent) && %w[type method kind].include?(name)
        return allowed_context?(path, 'recipient.type') ? 'recipient.type' : nil
      end
      return "error.#{name}" if %w[error failure].include?(parent) && %w[code message].include?(name)

      exact = ALIASES.find { |_, aliases| aliases.include?(name) }&.first
      return nil if exact == 'provider_operation_id' && name == 'id' && !response
      return allowed_context?(path, exact) ? exact : nil if exact

      description = field.dig('schema', 'description').to_s
      return 'amount' if allowed_context?(path, 'amount') && description.match?(/\bamount\b|сумма/i) && %w[number integer].include?(field.dig('schema', 'type'))
      return 'external_id' if allowed_context?(path, 'external_id') && description.match?(/merchant.{0,20}(?:id|reference)|id.{0,30}мерчант/i)

      nil
    end

    def alias?(field)
      name = normalize(field['path'].split('.').last)
      ALIASES.values.any? { |aliases| aliases.include?(name) } || %w[type method kind code message].include?(name)
    end

    private

    # смотрим весь путь чтобы не взять customer.phone за телефон получателя
    def allowed_context?(path, canonical)
      parents = path.split('.')[0...-1].map { |part| normalize(part) }
      if canonical.to_s.start_with?('recipient.')
        return true if parents.empty?

        recipients = %w[recipient beneficiary destination payee]
        wrappers = %w[data result payment payout transfer transaction operation card sbp]
        return parents.any? { |parent| recipients.include?(parent) } && parents.all? { |parent| (recipients + wrappers).include?(parent) }
      end
      return true unless %w[amount currency external_id provider_operation_id status event created_at completed_at].include?(canonical)

      allowed = %w[data result payment payout transfer transaction operation]
      allowed += %w[funds money] if %w[amount currency].include?(canonical)
      parents.all? { |parent| allowed.include?(parent) }
    end

    def normalize(value)
      value.gsub(/([a-z\d])([A-Z])/, '\1_\2').tr('-', '_').downcase
    end
  end

  class OperationClassifier
    ROLE_PATTERNS = {
      'create' => /\b(create|initiate|submit|send|make)\b|созда|отправить/i,
      'status' => /\b(status|retrieve|fetch|lookup|check)\b|статус|проверить/i,
      'cancel' => /\b(cancel|void|revoke)\b|отмен/i,
      'webhook' => /\b(webhooks?|callbacks?|notification)\b|уведомлен/i,
      'balance' => /\bbalance\b|баланс/i
    }.freeze

    # по пути названию и описанию определяем роль endpoint а при споре просим overrides
    def classify(operation)
      sources = [
        [operation['id'], 6], [operation['path'], 4], [operation['tags'].join(' '), 3],
        [operation['summary'], 3], [operation['description'], 1]
      ]
      scores = ROLE_PATTERNS.to_h do |role, pattern|
        score = sources.sum { |text, weight| normalize(text).match?(pattern) ? weight : 0 }
        [role, score]
      end
      if operation['method'] == 'get'
        scores['status'] += 3 if operation['path'].include?('{')
        scores['status'] += 2 if operation['response_fields'].any? { |field| %w[status state].include?(field['path']) }
      elsif operation['method'] == 'post'
        scores['create'] += 2 if operation['fields'].any? { |field| %w[amount total_amount value].include?(field['path']) }
      end
      candidates = scores.map { |role, score| { 'role' => role, 'score' => score } }.sort_by { |item| [-item['score'], item['role']] }
      first, second = candidates
      certain = first['score'] >= 4 && first['score'] - second['score'] >= 2
      { 'role' => certain ? first['role'] : 'unknown',
        'confidence' => certain ? (first['score'] >= 8 ? 'high' : 'medium') : 'unresolved', 'candidates' => candidates }
    end

    private

    def normalize(text)
      text.to_s.gsub(/([a-z])([A-Z])/, '\1 \2').tr('_/-', '   ')
    end
  end
end
