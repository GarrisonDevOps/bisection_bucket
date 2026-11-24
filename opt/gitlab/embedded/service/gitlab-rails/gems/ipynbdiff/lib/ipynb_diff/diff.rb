# frozen_string_literal: true

# Custom differ for Jupyter Notebooks
module IpynbDiff
  require 'delegate'

  # The result of a diff object
  class Diff < SimpleDelegator
    require 'diffy'
    require 'ipynb_diff/interruptible_text_diff'

    attr_reader :from, :to

    def initialize(from, to, diffy_opts, interruptible: false)
      text_diff_class = interruptible ? InterruptibleTextDiff : Diffy::Diff

      super(text_diff_class.new(from.as_text, to.as_text, **diffy_opts))

      @from = from
      @to = to
    end
  end
end
