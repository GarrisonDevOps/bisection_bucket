# frozen_string_literal: true

module Ai
  module Context
    module Dependencies
      module ConfigFiles
        class CsharpNuget < Base
          def self.file_name_glob
            '*.csproj'
          end

          def self.lang_name
            'C#'
          end

          private

          ### Example format:
          #
          # <Project Sdk="Microsoft.NET.Sdk">
          #   <ItemGroup>
          #     <PackageReference Include="Microsoft.Extensions.Hosting" Version="6.0.1" />
          #     <PackageReference Include="MessagePack" />
          #     <PackageReference Include="Microsoft.EntityFrameworkCore.Design">
          #       <PrivateAssets>all</PrivateAssets>
          #     </PackageReference>
          #   </ItemGroup>
          # </Project>
          #
          def extract_libs
            doc = Nokogiri::XML(content)
            raise ParsingErrors::DeserializationException, 'content is not valid XML' if doc.errors.any?

            doc.remove_namespaces!

            doc.xpath('//ItemGroup/PackageReference').map do |dep|
              name = dep['Include']
              version = dep['Version']

              Lib.new(name: name, version: version)
            end
          end
        end
      end
    end
  end
end
