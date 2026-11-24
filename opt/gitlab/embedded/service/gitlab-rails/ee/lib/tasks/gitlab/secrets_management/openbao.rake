# frozen_string_literal: true

namespace :gitlab do
  namespace :secrets_management do
    namespace :openbao do
      desc 'GitLab | Secrets Management | Clone and checkout OpenBao'
      task :download_or_clone, [:dir, :repo] => :gitlab_environment do |_, args|
        warn_user_is_not_gitlab

        unless args.dir.present?
          abort %(Please specify the directory where you want to clone OpenBao into
Usage: rake "gitlab:secrets_management:openbao:clone[/installation/dir]")
        end

        args.with_defaults(repo: 'https://gitlab.com/gitlab-org/govern/secrets-management/openbao-internal.git')

        version = SecretsManagement::SecretsManagerClient.expected_server_version
        binary_target_path = "#{args.dir}/bin/bao"

        arch_map = {
          'aarch64' => 'arm64',
          'x86_64' => 'amd64'
        }

        # As per https://gitlab.com/gitlab-org/govern/secrets-management/openbao-internal/-/packages/
        checksums_sha256 = {
          'bao-darwin-amd64' => '61e3b3c4e7cdbeb5d94b2490814134e817109b2fe51924dc5e08d444757e0c91',
          'bao-darwin-arm64' => 'bced76fd4afa883385056351316792b7383ab7a8a6858ba37ebfa917254ae7ee',
          'bao-linux-amd64' => 'c2feaef48c639aaccd3091484ddf54fc58509a6ef166922ac844e069526b750e',
          'bao-linux-arm64' => '091bd99687125109d2eab0409d531dd3bfb3099c05d2687ed973f8c6e3ec93c3'
        }

        os = Gem::Platform.local.os
        arch = Gem::Platform.local.cpu
        arch = arch_map.fetch(arch, arch)

        package_file = "bao-#{os}-#{arch}"

        puts "Downloading binary `#{package_file}` from #{args.repo}"

        downloaded = download_package_file_version(
          version: version,
          repo: args.repo,
          package_name: 'openbao-internal',
          package_file: package_file,
          package_checksums_sha256: checksums_sha256,
          target_path: binary_target_path
        )

        if downloaded
          File.chmod(0o755, binary_target_path)
          # Needed for TestEnv#component_needs_update?
          File.write("#{args.dir}/VERSION", version)
        else
          puts "Checkout from #{args.repo}"

          checkout_or_clone_version(
            version: version,
            repo: args.repo,
            target_dir: args.dir,
            clone_opts: %w[--depth 1 --recurse-submodules],
            checkout_opts: %w[--recurse-submodules]
          )
        end
      end

      namespace :recovery_key do
        desc 'GitLab | Secrets Management | Fetch recovery key from OpenBao and store in database'
        task :store, [] => :gitlab_environment do
          if SecretsManagement::RecoveryKey.active.take
            puts "Recovery key already generated in OpenBao and stored in the GitLab database. " \
              "Use recovery_key:show to view it."
            next
          end

          privileged_jwt = SecretsManagement::GlobalSecretsManagerJwt.new.encoded
          secrets_manager_client = SecretsManagement::SecretsManagerClient.new(jwt: privileged_jwt)

          result = secrets_manager_client.init_rotate_recovery
          if result["data"].key? "keys"
            key = result["data"]["keys"][0]

            # Store key, and then mark it as active. This way, the key is
            # persisted even if there's some error when trying to make it the
            # only active key.
            new_key = SecretsManagement::RecoveryKey.new do |nk|
              nk.active = false
              nk.key = key
            end
            new_key.save!

            puts "Persisted key to the database."

            new_key.active = true
            new_key.save!

            puts "Marked key as active."

            new_key
          else
            puts <<~MSG
              OpenBao recovery key already generated and consumed — it cannot be retrieved via this task.
              If you previously ran recovery_key:store, run recovery_key:show to view the key stored in the GitLab database.
              If you previously ran recovery_key:fetch, retrieve the key from the external store where you saved it.
            MSG

            # Avoid leaving rotation in an inconsistent state.
            secrets_manager_client.cancel_rotate_recovery

            nil
          end
        rescue SecretsManagement::SecretsManagerClient::ApiError => e
          puts "Cannot get key, exception: #{e}"
          Gitlab::ErrorTracking.track_and_raise_exception(e)
        end

        desc 'GitLab | Secrets Management | Fetch recovery key from OpenBao and display without storing'
        task :fetch, [] => :gitlab_environment do
          if SecretsManagement::RecoveryKey.active.take
            puts "A recovery key is already stored in the database. Use recovery_key:show to view it."
            next
          end

          print "WARNING: This will generate and display the recovery key from OpenBao in this terminal. " \
            "The key will NOT be stored in the GitLab database. " \
            "This key can only be retrieved from OpenBao once — save it immediately. Continue? [y/N]: "
          $stdout.flush
          input = $stdin.gets.to_s.chomp

          unless input.casecmp('y') == 0
            puts "Aborted."
            next
          end

          privileged_jwt = SecretsManagement::GlobalSecretsManagerJwt.new.encoded
          secrets_manager_client = SecretsManagement::SecretsManagerClient.new(jwt: privileged_jwt)

          result = secrets_manager_client.init_rotate_recovery
          if result["data"].key? "keys"
            key = result["data"]["keys"][0]
            puts "\nRecovery key (store securely — do not log or share outside a secure channel):"
            puts key
            puts "\nThis key cannot be retrieved from OpenBao again. Store it in a secure location now."
          else
            puts <<~MSG
              OpenBao recovery key already generated and consumed — it cannot be retrieved via this task.
              If you previously ran recovery_key:store, run recovery_key:show to view the key stored in the GitLab database.
              If you previously ran recovery_key:fetch, retrieve the key from the external store where you saved it.
            MSG

            # Avoid leaving rotation in an inconsistent state.
            secrets_manager_client.cancel_rotate_recovery

            nil
          end
        rescue SecretsManagement::SecretsManagerClient::ApiError => e
          puts "Cannot get key, exception: #{e}"
          Gitlab::ErrorTracking.track_and_raise_exception(e)
        end

        desc 'GitLab | Secrets Management | Display the recovery key stored in the database'
        task :show, [] => :gitlab_environment do
          recovery_key = SecretsManagement::RecoveryKey.active.take

          unless recovery_key
            puts "No recovery key found in database. Run recovery_key:store first."
            next
          end

          print "WARNING: This will display the recovery key in plaintext. Continue? [y/N]: "
          $stdout.flush
          input = $stdin.gets.to_s.chomp

          unless input.casecmp('y') == 0
            puts "Aborted."
            next
          end

          puts "\nRecovery key (store securely — do not log or share outside a secure channel):"
          puts recovery_key.key
        end
      end

      namespace :root_token do
        desc 'GitLab | Secrets Management | Generate an OpenBao root token from the recovery key'
        task :generate, [] => :gitlab_environment do
          SecretsManagement::RakeTask::GenerateRootToken.new.execute
        end
      end

      namespace :secrets_manager_policy do
        desc 'GitLab | Secrets Management | Update the secrets_manager OpenBao policy to the one shipped with GitLab'
        task :update, [] => :gitlab_environment do
          SecretsManagement::RakeTask::UpdateSecretsManagerPolicy.new(dry_run: ENV['DRY_RUN'] != 'false').execute
        end
      end
    end
  end
end
