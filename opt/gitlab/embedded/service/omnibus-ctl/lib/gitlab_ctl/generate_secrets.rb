# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

# For testing purposes, if the first path cannot be found load the second
begin
  require_relative '../../../../cookbooks/package/libraries/helpers/secrets_helper'
rescue LoadError
  require_relative '../../../gitlab-cookbooks/package/libraries/helpers/secrets_helper'
end

module GitlabCtl
  class GenerateSecrets
    DEPRECATION_MESSAGE ||= <<~EOS.freeze
      WARNING: 'gitlab-ctl generate-secrets' is deprecated and will be removed in GitLab 20.0.
      Use 'gitlab-ctl reconfigure' to generate secrets instead and copy the resulting /etc/gitlab/gitlab-secrets.json file.
      For more information, see https://gitlab.com/gitlab-org/omnibus-gitlab/-/work_items/8639.
    EOS

    USAGE ||= <<~EOS.freeze
    Usage:
      gitlab-ctl generate-secrets -f|--file FILE

        f, --file=FILE                  Output secrets to file

    #{DEPRECATION_MESSAGE.chomp}
    EOS
    class << self
      def parse_options(args)
        options = {}

        OptionParser.new do |opts|
          opts.on('-fFILE', '--file=FILE', "Output secrets to file") do |f|
            options[:secrets_path] = f
          end
          opts.on('-h', '--help', 'Usage help') do
            Kernel.puts USAGE
            Kernel.exit 0
          end
        end.parse!(args)
        raise OptionParser::ParseError, "Option --file must be specified." unless options.key?(:secrets_path)

        options
      end
    end
  end
end
