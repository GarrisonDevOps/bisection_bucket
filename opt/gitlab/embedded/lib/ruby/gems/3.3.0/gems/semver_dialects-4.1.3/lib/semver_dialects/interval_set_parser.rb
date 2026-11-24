# frozen_string_literal: true

# IntervalSetParser parses a string that represents an interval set
# in a syntax that's specific to a package type.
module SemverDialects
  module IntervalSetParser # rubocop:todo Style/Documentation
    # parse parses a string and returns an IntervalSet.
    # The string is expected to be in a syntax that's specific the given package type.
    def self.parse(typ, interval_set_string)
      IntervalSet.new.tap do |set|
        translate(typ, interval_set_string).each do |interval_str|
          set << IntervalParser.parse(typ, interval_str)
        end
      end
    end

    def self.translate(typ, interval_set_string)
      case typ
      when 'maven'
        translate_maven(interval_set_string)
      when 'npm'
        translate_npm(interval_set_string)
      when 'conan'
        translate_conan(interval_set_string)
      when 'nuget'
        translate_nuget(interval_set_string)
      when 'go'
        translate_go(interval_set_string)
      when 'gem'
        translate_gem(interval_set_string)
      when 'pypi'
        translate_pypi(interval_set_string)
      when 'packagist'
        translate_packagist(interval_set_string)
      when 'cargo'
        translate_cargo(interval_set_string)
      when 'swift'
        translate_swift(interval_set_string)
      when 'pub'
        translate_pub(interval_set_string)
      else
        raise UnsupportedPackageTypeError, typ
      end
    end

    def self.translate_npm(interval_set_string)
      interval_set_string.split('||').map do |item|
        add_missing_operator(single_space_after_operator(item.strip.gsub(/&&/, ' ')))
      end
    end

    def self.translate_conan(interval_set_string)
      translate_npm(interval_set_string)
    end

    def self.translate_go(interval_set_string)
      translate_gem(interval_set_string)
    end

    def self.translate_gem(interval_set_string)
      interval_set_string.split('||').map do |item|
        add_missing_operator(single_space_after_operator(item.strip.gsub(/\s+/, ' ')))
      end
    end

    def self.translate_packagist(interval_set_string)
      translate_pypi(interval_set_string)
    end

    def self.translate_pypi(interval_set_string)
      interval_set_string.split('||').map do |item|
        add_missing_operator(single_space_after_operator(comma_to_space(item)))
      end
    end

    def self.translate_nuget(interval_set_string)
      translate_maven(interval_set_string)
    end

    def self.translate_maven(interval_set_string)
      lexing_maven_interval_set_string(interval_set_string).map { |item| translate_mvn_version_item(item) }
    end

    def self.translate_cargo(interval_set_string)
      translate_npm(interval_set_string)
    end

    def self.translate_swift(interval_set_string)
      translate_npm(interval_set_string)
    end

    def self.translate_pub(interval_set_string)
      translate_npm(interval_set_string)
    end

    def self.add_missing_operator(interval_set_string)
      starts_with_operator?(interval_set_string) ? interval_set_string : "=#{interval_set_string}"
    end

    def self.single_space_after_operator(interval_set_string)
      interval_set_string.gsub(/([>=<]+) +/, '\1').gsub(/\s+/, ' ')
    end

    def self.starts_with_operator?(version_item)
      version_item.match(/^[=><]/) ? true : false
    end

    def self.comma_to_space(interval_set_string)
      interval_set_string.strip.gsub(/,/, ' ')
    end

    def self.lexing_maven_interval_set_string(interval_set_string)
      open = false
      substring = ''
      ret = []
      interval_set_string.each_char do |c|
        case c
        when '(', '['
          if open
            puts "malformed maven version string #{interval_set_string}"
            exit(-1)
          else
            unless substring.empty?
              ret << substring
              substring = ''
            end
            open = true
            substring += c
          end
        when ')', ']'
          if !open
            puts "malformed maven version string #{interval_set_string}"
            exit(-1)
          else
            open = false
            substring += c
            ret << substring
            substring = ''
          end
        when ','
          substring += c if open
        when ' '
          # nothing to do
          substring += ''
        else
          substring += c
        end
      end
      if open
        puts "malformed maven version string #{interval_set_string}"
        exit(-1)
      end
      ret << substring unless substring.empty?
      ret
    end

    def self.parenthesized?(version_item)
      version_item.match(/^[(\[]/) && version_item.match(/[\])]$/)
    end

    def self.translate_mvn_version_item(version_item)
      content = ''
      parens_pattern = ''
      if parenthesized?(version_item)
        content = version_item[1, version_item.size - 2]
        parens_pattern = version_item[0] + version_item[version_item.size - 1]
        # special case -- unversal version range
        return '=*' if content.strip == ','
      else
        # according to the doc, if there is a plain version string in maven, it means 'starting from version x'
        # https://docs.oracle.com/middleware/1212/core/MAVEN/maven_version.htm#MAVEN8903
        content = "#{version_item},"
        parens_pattern = '[)'
      end

      args = content.split(',')
      first_non_empty_arg = args.find(&:range_present?)

      if content.start_with?(',')
        # {,y}
        case parens_pattern
        when '[]'
          "<=#{first_non_empty_arg}"
        when '()'
          "<#{first_non_empty_arg}"
        when '[)'
          "<#{first_non_empty_arg}"
        else
          # par_pattern == "(]"
          "<=#{first_non_empty_arg}"
        end
      elsif content.end_with?(',')
        # {x,}
        case parens_pattern
        when '[]'
          ">=#{first_non_empty_arg}"
        when '()'
          ">#{first_non_empty_arg}"
        when '[)'
          ">=#{first_non_empty_arg}"
        else
          # par_pattern == "(]"
          ">#{first_non_empty_arg}"
        end
      elsif content[','].nil?
        # [x,x]
        "=#{content}"
      else
        case parens_pattern
        when '[]'
          ">=#{args[0]} <=#{args[1]}"
        when '()'
          ">#{args[0]} <#{args[1]}"
        when '[)'
          ">=#{args[0]} <#{args[1]}"
        else
          # par_pattern == "(]"
          ">#{args[0]} <=#{args[1]}"
        end
      end
    end
  end
end
