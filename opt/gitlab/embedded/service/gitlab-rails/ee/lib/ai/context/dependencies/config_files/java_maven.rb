# frozen_string_literal: true

module Ai
  module Context
    module Dependencies
      module ConfigFiles
        class JavaMaven < Base
          def self.file_name_glob
            'pom.xml'
          end

          def self.lang_name
            'Java'
          end

          private

          ### Example format:
          #
          # <project>
          #     <dependencies>
          #         <dependency>
          #             <artifactId>junit-jupiter-engine</artifactId>
          #             <version>1.2.0</version>
          #         </dependency>
          #     </dependencies>
          # </project>
          #
          def extract_libs
            doc = Nokogiri::XML(content) # Always returns a Nokogiri::XML::Document object even with invalid content
            raise ParsingErrors::DeserializationException, 'content is not valid XML' if doc.errors.any?

            Array.wrap(dig_in(doc.to_hash, 'project', 'dependencies', 'dependency')).map do |dep|
              name = dig_in(dep, 'artifactId', '__content__')
              version = dig_in(dep, 'version', '__content__')

              Lib.new(name: name, version: version)
            end
          end
        end
      end
    end
  end
end
