# frozen_string_literal: true

module Ai
  module Context
    module Dependencies
      module ConfigFiles
        module Constants
          # When adding a new class to this list:
          # 1. Order by language (alaphabetically), then by precedence. Lock files should appear
          #    first before their non-lock file counterparts. Dependency managers that support
          #    multiple languages should be listed lower than ones that support only one language.
          # 2. Update doc/user/project/repository/code_suggestions/repository_xray.md
          #    #supported-languages-and-package-managers.
          #
          # This ordering affects the result of
          # ConfigFileParser#config_file_classes_by_path.
          #
          CONFIG_FILE_CLASSES = [
            ConfigFiles::CConanPy,
            ConfigFiles::CConanTxt,
            ConfigFiles::CVcpkg,
            ConfigFiles::CppConanPy,
            ConfigFiles::CppConanTxt,
            ConfigFiles::CppVcpkg,
            ConfigFiles::CsharpNuget,
            ConfigFiles::GoModules,
            ConfigFiles::JavaGradle,
            ConfigFiles::JavaMaven,
            ConfigFiles::JavascriptNpmLock,
            ConfigFiles::JavascriptNpm,
            ConfigFiles::KotlinGradle,
            ConfigFiles::PhpComposerLock,
            ConfigFiles::PhpComposer,
            ConfigFiles::PythonConda,
            ConfigFiles::PythonPip,
            ConfigFiles::PythonPoetryLock,
            ConfigFiles::PythonPoetry,
            ConfigFiles::RubyGemsLock
          ].freeze
        end
      end
    end
  end
end
