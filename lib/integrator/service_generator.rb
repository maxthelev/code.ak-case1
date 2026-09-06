# frozen_string_literal: true

require 'erb'
require 'json'
require_relative 'runtime_config_builder'

module Integrator
  class ServiceGenerator
    def initialize(ir)
      @ir = ir
    end

    # данные вставляем как ruby-строку чтобы текст спеки не стал исполняемым кодом
    def render
      provider = @ir.fetch('provider')
      raise ArgumentError, 'provider must be a safe slug' unless /\A[a-z][a-z0-9_]*\z/.match?(provider)

      class_name = provider.split('_').map(&:capitalize).join + 'Service'
      config_literal = JSON.generate(RuntimeConfigBuilder.new(@ir).build).dump
      template = File.read(File.expand_path('../../templates/service.rb.erb', __dir__), encoding: 'UTF-8')
      ERB.new(template, trim_mode: '-').result_with_hash(class_name: class_name, config_literal: config_literal)
    end
  end
end
