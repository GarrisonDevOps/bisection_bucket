# frozen_string_literal: true

# monkey-patch String class
class String
  def unwrap
    s = self
    s = s[1..s.length - 1] if s.start_with?('(')
    s = s[0..s.length - 2] if s.end_with?(')')
    s
  end

  def range_present?
    !empty?
  end

  def number?
    !!Integer(self, exception: false)
  end

  def initial
    self[0, 1]
  end

  def unquote
    delete_suffix('"').delete_prefix('"').delete_suffix('\'').delete_prefix('\'')
  end

  def csv_unquote
    unquote.unquote.unquote
  end

  def remove_trailing_number
    gsub(/([^\d]*)\d+$/, '\1')
  end

  def chars_only
    gsub(/[^0-9A-Za-z]/, '')
  end
end
