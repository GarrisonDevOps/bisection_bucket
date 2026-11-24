---
stage: Software Supply Chain Security
group: Authentication
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: Sessions actives
---

{{< details >}}

- Édition : Gratuite, GitLab Premium, GitLab Ultimate
- Offre : GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

GitLab répertorie tous les appareils qui se sont connectés à votre compte. Vous pouvez consulter les sessions et révoquer celles que vous ne reconnaissez pas.

## Lister toutes les sessions actives {#list-all-active-sessions}

Pour lister toutes les sessions actives :

1. Dans le coin supérieur droit, sélectionnez votre avatar.
1. Sélectionnez **Modifier le profil**.
1. Dans la barre latérale gauche, sélectionnez **Accès** > **Sessions actives**.

![Liste des sessions actives](img/active_sessions_list_v12_7.png)

## Limite des sessions actives {#active-sessions-limit}

GitLab permet aux utilisateurs d'avoir jusqu'à 100 sessions actives simultanément. Si le nombre de sessions actives dépasse 100, les plus anciennes sont supprimées.

## Révoquer une session {#revoke-a-session}

Pour révoquer une session active :

1. Dans le coin supérieur droit, sélectionnez votre avatar.
1. Sélectionnez **Modifier le profil**.
1. Dans la barre latérale gauche, sélectionnez **Accès** > **Sessions actives**.
1. Sélectionnez **Révoquer** en regard d'une session. La session en cours ne peut pas être révoquée, car cela vous déconnecterait de GitLab.

> [!note]
> Lorsqu'une session est révoquée, tous les jetons **Se souvenir de moi** pour tous les appareils sont révoqués. Pour en savoir plus sur **Se souvenir de moi**, consultez [les cookies utilisés pour la connexion](_index.md#cookies-used-for-sign-in).

## Révoquer des sessions via la console Rails {#revoke-sessions-through-the-rails-console}

Vous pouvez également révoquer des sessions utilisateur via la console Rails. Vous pouvez utiliser cette méthode pour révoquer plusieurs sessions en même temps.

### Révoquer toutes les sessions pour tous les utilisateurs {#revoke-all-sessions-for-all-users}

Pour révoquer toutes les sessions pour tous les utilisateurs :

1. [Démarrez une session de console Rails](../../administration/operations/rails_console.md#starting-a-rails-console-session).
1. Facultatif. Listez toutes les sessions actives avec la commande suivante :

   ```ruby
   # Show all users with active sessions
    puts "=== Currently Logged In Users ==="
    User.find_each do |user|
        sessions = ActiveSession.list(user)
        if sessions.any?
            puts "\n#{user.username} (#{user.name}):"
            sessions.each do |session|
                puts "  - IP: #{session.ip_address}, Browser: #{session.browser}, Last active: #{session.updated_at}"
            end
        end
    end
   ```

1. Révoquez toutes les sessions avec la commande suivante :

   ```ruby
   User.find_each do |user|
      ActiveSession.destroy_all_but_current(user, nil)
   end
   ```

1. Facultatif. Confirmez que toutes les sessions ont été révoquées en exécutant à nouveau la commande « Lister toutes les sessions actives ».

### Révoquer toutes les sessions pour tous les utilisateurs d'un groupe {#revoke-all-sessions-for-all-users-of-a-group}

1. Enregistrez le script suivant sur votre instance GitLab. Par exemple, `scripts/session_revocation/revoke_group_sessions.rb`.

   ```ruby
   # frozen_string_literal: true
   #
   # Revoke all active sessions for members of a group, including:
   # - Direct and inherited members of the top-level group
   # - Direct members of all subgroups
   # - Members invited via group shares at the top-level and subgroup level
   #
   # Usage (Rails console):
   #   DRY_RUN = true
   #   GROUP_IDENTIFIER = 'your-group-path' # or numeric ID
   #   load 'scripts/session_revocation/revoke_group_sessions.rb'

   DRY_RUN = true unless defined?(DRY_RUN)
   # Replace `your-group-path` with your group ID or the full path to your group
   GROUP_IDENTIFIER = 'your-group-path' unless defined?(GROUP_IDENTIFIER)

   # ---------------------------------------------------------------

   def find_group(identifier)
      # Try finding by full path first (handles numeric group names)
      group = Group.find_by_full_path(identifier.to_s)
      return group if group

      # Fallback to ID lookup if path not found and identifier is numeric
      if identifier.is_a?(Integer) || identifier.to_s.match?(/\A\d+\z/)
         Group.find_by(id: identifier)
      end
   end

   def collect_member_user_ids(group)
      user_ids = Set.new

      # Direct and inherited members of the top-level group
      user_ids.merge(group.members_with_parents.pluck(:user_id))

      # Members invited via group shares into the top-level group
      group.shared_with_group_links.each do |link|
         user_ids.merge(link.shared_with_group.members_with_parents.pluck(:user_id))
      end

      # Traverse all subgroups
      group.descendants.find_each do |subgroup|
         # Direct members of each subgroup
         user_ids.merge(subgroup.members.pluck(:user_id))

         # Members invited via group shares into each subgroup
         subgroup.shared_with_group_links.each do |link|
            user_ids.merge(link.shared_with_group.members_with_parents.pluck(:user_id))
         end
      end

      user_ids.to_a
   end

   def revoke_sessions_for_group(group, dry_run:)
      member_user_ids = collect_member_user_ids(group)

      puts "Found #{member_user_ids.count} unique members in group '#{group.full_path}' (including subgroups and group shares)"

      # Only process active, non-bot human users to avoid unnecessary Redis lookups
      users = User.active.human.id_in(member_user_ids)

      revoked_sessions = 0
      affected_users = []
      skipped_users = []

      users.find_each do |user|
         sessions = ActiveSession.list(user)

         if sessions.empty?
            skipped_users << user.username
            next
         end

         session_ids = sessions.map(&:session_private_id).compact

         if session_ids.empty?
            puts "  [WARN] User #{user.username} has sessions but all session_private_ids are nil, skipping."
            skipped_users << user.username
            next
         end

         unless dry_run
            Gitlab::Redis::Sessions.with do |redis|
               ActiveSession.destroy_sessions(redis, user, session_ids)
            end

            # Emit audit event for security traceability
            Gitlab::AppLogger.info(
               message: "Sessions revoked via admin script",
               user_id: user.id,
               username: user.username,
               session_count: session_ids.size,
               group: group.full_path,
               performed_at: Time.current.iso8601
            )
         end

         revoked_sessions += session_ids.size
         affected_users << user.username
      end

      [revoked_sessions, affected_users, skipped_users]
   end

   # ---------------------------------------------------------------

   group = find_group(GROUP_IDENTIFIER)

   if group.nil?
      puts "ERROR: Group '#{GROUP_IDENTIFIER}' not found. Aborting."
   end

   puts "=== Session Revocation #{DRY_RUN ? '(DRY RUN)' : '(LIVE)'} ==="
   puts "Group: #{group.full_path} (ID: #{group.id})"
   puts

   revoked_sessions, affected_users, skipped_users = revoke_sessions_for_group(group, dry_run: DRY_RUN)

   prefix = DRY_RUN ? "[DRY RUN] Would revoke" : "Revoked"
   puts "#{prefix} #{revoked_sessions} sessions for #{affected_users.size} users"
   puts "Users affected: #{affected_users.sort.join(', ')}" if affected_users.any?
   puts "Users skipped (no active sessions): #{skipped_users.size}" if skipped_users.any?

   if DRY_RUN && revoked_sessions.positive?
      puts "\nTo actually revoke sessions, set DRY_RUN = false and run again."
   end
   ```

1. [Démarrez une session de console Rails](../../administration/operations/rails_console.md#starting-a-rails-console-session).
1. Exécutez la commande suivante pour cibler le groupe. Remplacez `your-group-path` par l'ID de votre groupe ou le chemin complet vers votre groupe :

   ```ruby
   GROUP_IDENTIFIER = 'your-group-path'
   ```

1. Exécutez la commande suivante pour lister toutes les sessions actives dans le groupe :

   ```ruby
   DRY_RUN = true
   load 'scripts/session_revocation/revoke_group_sessions.rb'
   ```

1. Exécutez la commande suivante pour révoquer toutes les sessions dans le groupe :

   ```ruby
   DRY_RUN = false
   load 'scripts/session_revocation/revoke_group_sessions.rb'
   ```

1. Exécutez la commande suivante pour vérifier que toutes les sessions sont fermées. La sortie doit indiquer 0 session active :

   ```ruby
   DRY_RUN = true
   load 'scripts/session_revocation/revoke_group_sessions.rb'
   ```

### Révoquer toutes les sessions pour un utilisateur {#revoke-all-sessions-for-a-user}

Pour révoquer toutes les sessions pour un utilisateur spécifique :

1. [Démarrez une session de console Rails](../../administration/operations/rails_console.md#starting-a-rails-console-session).
1. Trouvez l'utilisateur avec les commandes suivantes :

   - Par nom d'utilisateur :

     ```ruby
     user = User.find_by_username 'exampleuser'
     ```

   - Par ID utilisateur :

     ```ruby
     user = User.find(123)
     ```

   - Par adresse e-mail :

     ```ruby
     user = User.find_by(email: 'user@example.com')
     ```

1. Facultatif. Listez toutes les sessions actives pour l'utilisateur avec la commande suivante :

   ```ruby
   ActiveSession.list(user)
   ```

1. Révoquez toutes les sessions avec la commande suivante :

   ```ruby
   ActiveSession.list(user).each { |session| ActiveSession.destroy_session(user, session.session_private_id) }
   ```

1. Vérifiez que toutes les sessions sont fermées avec la commande suivante :

   ```ruby
   # If all sessions are closed, returns an empty array.
   ActiveSession.list(user)
   ```
