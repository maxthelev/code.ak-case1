# frozen_string_literal: true

module Integrator
  class TextRules
    STATUS_MEANINGS = {
      'approved' => /\b(?:completed|approved|paid|settled|succeeded)\b|успеш|заверш/i,
      'rejected' => /\b(?:failed|rejected|cancelled|canceled|declined)\b|отклон|отмен|ошиб/i,
      'in_progress' => /\b(?:pending|processing|queued|in_progress)\b|обработ|ожида/i
    }.freeze
    ERROR_MEANINGS = {
      'insufficient_balance' => /insufficient.{0,20}balance|недостаточно средств/i,
      'invalid_credentials' => /invalid.{0,15}(?:credentials|api.key|token)|невалидн.{0,15}ключ/i,
      'rate_limit' => /rate.?limit|превышен лимит запросов/i,
      'validation_error' => /validation error|ошибка валидации/i
    }.freeze
    UNIT_RULES = [
      [/копе(?:й|ек|еч)|kope(?:ck|k)|\bcents?\b/i, 'minor', 100],
      [/\bminor (?:currency )?units?\b/i, 'minor', nil],
      [/\bmajor (?:currency )?units?\b|\bin (?:dollars|euros|rubles)\b|в рублях/i, 'major', 1]
    ].freeze

    # ищем подсказки про единицы суммы и не выбираем между противоречивыми вариантами
    def units(text)
      UNIT_RULES.filter_map do |pattern, unit, factor|
        { 'unit' => unit, 'factor' => factor } if text.match?(pattern)
      end.uniq
    end

    # из описания поля берём условие обязательности но пропускаем отрицания
    def required_if(field)
      text = field.dig('schema', 'description').to_s
      return if text.match?(/\bnot\s+(?:required|mandatory)\b|\boptional\b|не\s*обязател/i)
      return unless text.match?(/обязател|\brequired\b|\bmandatory\b/i)

      match = text.match(/(?:для|при|when|if|for)\s+([\w.]+)\s*(?:==?|is|equals)\s*['"]?([\w.-]+)/i)
      return unless match

      parent = field['path'].split('.')[0...-1]
      condition = match[1].include?('.') ? match[1] : (parent + [match[1]]).join('.')
      { 'field' => field['path'], 'when' => { 'field' => condition, 'value' => match[2] },
        'source' => 'description', 'confidence' => 'medium' }
    end

    # проверяем текстовые условия только для реквизитов которые есть в схеме
    def operation_conditions(operation)
      operation['description'].scan(/([\w.]+)\s+(?:is\s+)?(?:required|mandatory|обязател\S*)\s+(?:if|when|for|при|для)\s+([\w.]+)\s*(?:==?|is|equals)\s*['"]?([\w.-]+)/i).filter_map do |target, condition, value|
        field = operation['fields'].find { |item| item['path'] == target || item['path'].split('.').last == target }
        next unless field
        condition_field = operation['fields'].find { |item| item['path'] == condition || item['path'].split('.').last == condition }
        next unless condition_field

        { 'field' => field['path'], 'when' => { 'field' => condition_field['path'], 'value' => value },
          'source' => 'description', 'confidence' => 'medium' }
      end
    end

    # отрицание успеха нельзя превращать в approved по одному знакомому слову
    def status_meaning(status, description)
      meaning = description.to_s.match(/(?:\A|[;\n,.]\s*)\s*#{Regexp.escape(status.to_s)}\s*[:=—-]\s*([^;\n,.]+)/i)&.[](1)
      return unless meaning

      return false if meaning.match?(/\b(?:not|never|no|without)\b|\b(?:isn|wasn|hasn|haven|doesn|didn)['’]t\b|(?:\A|\s)не(?:\s|заверш|оплач|успеш)/i)
      candidates = STATUS_MEANINGS.filter_map { |canonical, pattern| canonical if meaning.match?(pattern) }
      candidates.length == 1 ? candidates.first : false
    end

    def error_meaning(description)
      candidates = ERROR_MEANINGS.filter_map { |canonical, pattern| canonical if description.to_s.match?(pattern) }
      candidates.first if candidates.length == 1
    end

    # собираем только явно описанные части подписи остальное остаётся для уточнения
    def signature(operation)
      parameters = operation['parameters']
      signature_header = parameters.find do |parameter|
        parameter['in'] == 'header' && [parameter['name'], parameter['description']].join(' ').match?(/signature|hmac|подпись/i)
      end
      text = [operation['description'], *parameters.map { |parameter| parameter['description'] }].join(' ')
      algorithm = 'HMAC-SHA256' if text.match?(/HMAC[\s-]*SHA[\s-]*256/i)
      signed_data = 'raw_body' if text.match?(/raw\s+(?:http\s+)?(?:request\s+)?body/i)
      encoding = if text.match?(/\bhex(?:adecimal)?\b/i)
                   'hex'
                 elsif text.match?(/\bbase64\b/i)
                   'base64'
                 end
      { 'algorithm' => algorithm, 'header' => signature_header && signature_header['name'],
        'signed_data' => signed_data, 'encoding' => encoding, 'source' => 'description', 'confidence' => 'medium' }
    end

    # ищем объявленный ключ повтора вместо того чтобы придумывать новый заголовок
    def idempotency(parameters, description = '')
      parameter = parameters.find do |item|
        [item['name'], item['description']].join(' ').match?(/idempoten|идемпотент/i)
      end
      return parameter.slice('name', 'in') if parameter
      name = description.match(/\b((?:X-)?Idempotency-Key)\b/i)&.[](1)
      { 'name' => name, 'in' => 'header' } if name && description.match?(/header|заголов/i)
    end
  end
end
