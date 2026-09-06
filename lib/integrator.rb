# frozen_string_literal: true

module Integrator
  class Error < StandardError; end
end

Dir[File.join(__dir__, 'integrator', '*.rb')].sort.each { |file| require file }
