---
stage: GitLab Delivery
group: Operate
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/marketing/product-and-technical-marketing/technical-writing/#assignments>
title: '자습서: 단일 노드 GitLab 인스턴스 설치 및 보안'
---

{{< details >}}

- 티어: Free, Premium, Ultimate
- 제공 서비스: GitLab Self-Managed

{{< /details >}}

<!-- vale gitlab_base.FutureTense = NO -->

이 튜토리얼에서는 최대 [20 RPS 또는 1,000명의 사용자](../../administration/reference_architectures/1k_users.md)를 수용할 수 있는 단일 노드 GitLab 인스턴스를 설치하고 안전하게 구성하는 방법을 알아봅니다.

단일 노드 GitLab 인스턴스를 설치하고 보안이 적용되도록 구성하려면:

1. [서버 보안](#secure-the-server)
1. [GitLab 설치](#install-gitlab)
1. [GitLab 구성](#configure-gitlab)
1. [다음 단계](#next-steps)

## 시작하기 전에 {#before-you-begin}

- 도메인 이름과 올바른 [DNS 설정](https://docs.gitlab.com/omnibus/settings/dns/)이 필요합니다.
- 다음과 같은 최소 사양이 있는 Debian 기반 서버:
  - 8개 vCPU
  - 7.2GB 메모리
  - 모든 리포지토리에 충분한 하드 드라이브 공간입니다. [저장소 요구 사항](../../install/requirements.md)에 대해 자세히 알아봅니다.

## 서버 보안 {#secure-the-server}

GitLab을 설치하기 전에 서버를 좀 더 안전하게 구성하는 것부터 시작합니다.

### 방화벽 구성 {#configure-the-firewall}

포트 22(SSH), 80(HTTP), 443(HTTPS)를 열어야 합니다. 클라우드 공급자의 콘솔을 사용하거나 서버 수준에서 이를 수행할 수 있습니다.

이 예제에서는 [`ufw`](https://wiki.ubuntu.com/UncomplicatedFirewall)를 사용하여 방화벽을 구성합니다. 모든 포트에 대한 액세스를 거부하고, 포트 80과 443을 허용하고, 마지막으로 포트 22에 대한 액세스 속도를 제한합니다. `ufw`는 지난 30초 동안 6개 이상의 연결을 시도한 IP 주소의 연결을 거부할 수 있습니다.

1. `ufw`을 설치합니다.

   ```shell
   sudo apt install ufw
   ```

1. `ufw` 서비스를 활성화하고 시작합니다:

   ```shell
   sudo systemctl enable --now ufw
   ```

1. 필요한 포트를 제외한 다른 모든 포트를 거부합니다:

   ```shell
   sudo ufw default deny
   sudo ufw allow http
   sudo ufw allow https
   sudo ufw limit ssh/tcp
   ```

1. 마지막으로 설정을 활성화합니다. 다음은 한 번만 실행되어야 하며, 패키지를 처음 설치할 때 실행됩니다. 메시지가 표시되면 yes (`y`)로 답변합니다:

   ```shell
   sudo ufw enable
   ```

1. 규칙이 있는지 확인합니다:

   ```shell
   $ sudo ufw status

   Status: active

   To                         Action      From
   --                         ------      ----
   80/tcp                     ALLOW       Anywhere
   443                        ALLOW       Anywhere
   22/tcp                     LIMIT       Anywhere
   80/tcp (v6)                ALLOW       Anywhere (v6)
   443 (v6)                   ALLOW       Anywhere (v6)
   22/tcp (v6)                LIMIT       Anywhere (v6)
   ```

### SSH 서버 구성 {#configure-the-ssh-server}

서버를 더욱 안전하게 하려면 SSH를 공개 키 인증을 허용하도록 구성하고 보안 위험이 될 수 있는 일부 기능을 비활성화합니다.

1. `/etc/ssh/sshd_config`을 편집기로 열고 다음이 있는지 확인합니다:

   ```plaintext
   PubkeyAuthentication yes
   PasswordAuthentication yes
   UsePAM yes
   UseDNS no
   AllowTcpForwarding no
   X11Forwarding no
   PrintMotd no
   PermitTunnel no
   # Allow client to pass locale environment variables
   AcceptEnv LANG LC_*
   # override default of no subsystems
   Subsystem       sftp    /usr/lib/openssh/sftp-server
   # Protocol adjustments, these would be needed/recommended in a FIPS or
   # FedRAMP deployment, and use only strong and proven algorithm choices
   Protocol 2
   Ciphers aes128-ctr,aes192-ctr,aes256-ctr
   HostKeyAlgorithms ecdsa-sha2-nistp256,ecdsa-sha2-nistp384,ecdsa-sha2-nistp521
   KexAlgorithms ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521
   Macs hmac-sha2-256,hmac-sha2-512
   ```

1. 파일을 저장하고 SSH 서버를 다시 시작합니다:

   ```shell
   sudo systemctl restart ssh
   ```

   SSH 재시작이 실패하면 `/etc/ssh/sshd_config`에 중복 항목이 없는지 확인합니다.

### Git 액세스를 위해 SSH를 사용하는 권한이 있는 사용자만 확인 {#ensure-only-authorized-users-are-using-ssh-for-git-access}

다음으로, 사용자가 유효한 GitLab 계정이 있고 SSH를 통해 Git 작업을 수행할 수 있어야 SSH를 사용하여 프로젝트를 다운로드할 수 없도록 합니다.

Git 액세스를 위해 SSH를 사용하는 권한이 있는 사용자만 확인하려면:

1. 다음을 `/etc/ssh/sshd_config` 파일에 추가합니다:

   ```plaintext
   # Ensure only authorized users are using Git
   AcceptEnv GIT_PROTOCOL
   ```

1. 파일을 저장하고 SSH 서버를 다시 시작합니다:

   ```shell
   sudo systemctl restart ssh
   ```

### 일부 커널 조정 {#make-some-kernel-adjustments}

커널 조정은 공격의 위협을 완전히 없애지는 못하지만 보안의 추가 계층을 추가합니다.

1. `/etc/sysctl.d` 아래에서 편집기로 새 파일을 열고(예: `/etc/sysctl.d/99-gitlab-hardening.conf`) 다음을 추가합니다.

   > [!note]
   > 이름 지정 및 소스 디렉터리는 처리 순서를 결정하며, 마지막으로 처리된 매개 변수가 이전 매개 변수를 재정의할 수 있으므로 중요합니다.

   ```plaintext
   ##
   ## The following help mitigate out of bounds, null pointer dereference, heap and
   ## buffer overflow bugs, use-after-free etc from being exploited. It does not 100%
   ## fix the issues, but seriously hampers exploitation.
   ##
   # Default is 65536, 4096 helps mitigate memory issues used in exploitation
   vm.mmap_min_addr=4096
   # Default is 0, randomize virtual address space in memory, makes vuln exploitation
   # harder
   kernel.randomize_va_space=2
   # Restrict kernel pointer access (for example, cat /proc/kallsyms) for exploit assistance
   kernel.kptr_restrict=2
   # Restrict verbose kernel errors in dmesg
   kernel.dmesg_restrict=1
   # Restrict eBPF
   kernel.unprivileged_bpf_disabled=1
   net.core.bpf_jit_harden=2
   # Prevent common use-after-free exploits
   vm.unprivileged_userfaultfd=0

   ## Networking tweaks ##
   ##
   ## Prevent common attacks at the IP stack layer
   ##
   # Prevent SYNFLOOD denial of service attacks
   net.ipv4.tcp_syncookies=1
   # Prevent time wait assassination attacks
   net.ipv4.tcp_rfc1337=1
   # IP spoofing/source routing protection
   net.ipv4.conf.all.rp_filter=1
   net.ipv4.conf.default.rp_filter=1
   net.ipv6.conf.all.accept_ra=0
   net.ipv6.conf.default.accept_ra=0
   net.ipv4.conf.all.accept_source_route=0
   net.ipv4.conf.default.accept_source_route=0
   net.ipv6.conf.all.accept_source_route=0
   net.ipv6.conf.default.accept_source_route=0
   # IP redirection protection
   net.ipv4.conf.all.accept_redirects=0
   net.ipv4.conf.default.accept_redirects=0
   net.ipv4.conf.all.secure_redirects=0
   net.ipv4.conf.default.secure_redirects=0
   net.ipv6.conf.all.accept_redirects=0
   net.ipv6.conf.default.accept_redirects=0
   net.ipv4.conf.all.send_redirects=0
   net.ipv4.conf.default.send_redirects=0
   ```

1. 다음 서버 재부팅에서 값이 자동으로 로드됩니다. 즉시 로드하려면:

   ```shell
   sudo sysctl --system
   ```

좋은 작업입니다. 서버를 보안으로 유지하기 위한 단계를 완료했습니다! 이제 GitLab을 설치할 준비가 되었습니다.

## GitLab 설치 {#install-gitlab}

서버가 설정되었으므로 GitLab을 설치합니다:

1. 필요한 종속성을 설치하고 구성합니다:

   ```shell
   sudo apt update
   sudo apt install -y curl openssh-server ca-certificates perl locales
   ```

1. 시스템 언어를 구성합니다:

   1. `/etc/locale.gen`을 편집하고 `en_US.UTF-8`의 주석이 제거되었는지 확인합니다.
   1. 언어를 다시 생성합니다:

      ```shell
      sudo locale-gen
      ```

1. GitLab 패키지 리포지토리를 추가하고 패키지를 설치합니다:

   ```shell
   curl --location "https://packages.gitlab.com/install/repositories/gitlab/gitlab-ee/script.deb.sh" | sudo bash
   ```

1. GitLab 패키지를 설치합니다. `GITLAB_ROOT_PASSWORD`로 강력한 비밀번호를 제공하고 `EXTERNAL_URL`을 자신의 것으로 바꿉니다. URL에 `https`을 포함하는 것을 잊지 마세요. 그러면 Let's Encrypt 인증서가 발급됩니다.

   ```shell
   sudo GITLAB_ROOT_PASSWORD="strong password" EXTERNAL_URL="https://gitlab.example.com" apt install gitlab-ee
   ```

   Let's Encrypt 인증서에 대해 자세히 알아보거나 자신의 인증서를 사용하려면 [GitLab을 TLS로 구성하는 방법](https://docs.gitlab.com/omnibus/settings/ssl/)을 읽어보세요.

   설정한 비밀번호가 선택되지 않으면 [루트 계정 비밀번호 재설정](../../security/reset_user_password.md#reset-the-root-password)에 대해 자세히 읽어보세요.
1. 몇 분 후 GitLab이 설치됩니다. `EXTERNAL_URL`에서 설정한 URL을 사용하여 로그인합니다. 사용자 이름으로 `root`을 사용하고 `GITLAB_ROOT_PASSWORD`에서 설정한 비밀번호를 사용합니다.

이제 GitLab을 구성할 시간입니다!

## GitLab 구성 {#configure-gitlab}

GitLab은 합리적인 기본 구성 옵션과 함께 제공됩니다. 이 섹션에서는 이러한 옵션을 변경하여 더 많은 기능을 추가하고 GitLab을 더욱 안전하게 만듭니다.

일부 옵션의 경우 **운영자** 영역 UI를 사용하고, 일부 옵션의 경우 GitLab 구성 파일인 `/etc/gitlab/gitlab.rb`을 편집합니다.

### NGINX 구성 {#configure-nginx}

NGINX는 GitLab 인스턴스에 액세스하는 데 사용되는 웹 인터페이스를 제공하는 데 사용됩니다. NGINX를 더욱 안전하게 구성하는 방법에 대한 자세한 내용은 [NGINX 강화](../../security/hardening_configuration_recommendations.md#nginx)를 참조하세요.

### 이메일 구성 {#configure-emails}

다음으로 이메일 서비스를 설정하고 구성합니다. 이메일은 새 사용자 계정 확인, 비밀번호 재설정, GitLab 활동 알림에 중요합니다.

#### SMTP 구성 {#configure-smtp}

이 튜토리얼에서는 [SMTP](https://docs.gitlab.com/omnibus/settings/smtp/) 서버를 설정하고 [Mailgun](https://www.mailgun.com/) SMTP 공급자를 사용합니다.

먼저 로그인 자격 증명을 포함할 암호화된 파일을 만든 다음 Linux 패키지에 대해 SMTP를 구성합니다:

1. SMTP 서버의 자격 증명을 포함하는 YAML 파일(예: `smtp.yaml`)을 만듭니다.

   SMTP 비밀번호는 Ruby 또는 YAML에서 사용되는 문자열 구분 기호(예: `'`)를 포함하지 않아야 하며, 이는 구성 설정 처리 중에 예상치 못한 동작을 피하기 위함입니다.

   ```shell
   user_name: '<SMTP user>'
   password: '<SMTP password>'
   ```

1. 파일을 암호화합니다:

   ```shell
   cat smtp.yaml | sudo gitlab-rake gitlab:smtp:secret:write
   ```

   기본적으로 암호화된 파일은 `/var/opt/gitlab/gitlab-rails/shared/encrypted_settings/smtp.yaml.enc`에 저장됩니다.
1. YAML 파일을 제거합니다:

   ```shell
   rm -f smtp.yaml
   ```

1. `/etc/gitlab/gitlab.rb`을 편집하고 SMTP 설정의 나머지를 설정합니다. `gitlab_rails['smtp_user_name']` 및 `gitlab_rails['smtp_password']`이 없는지 확인합니다. 이미 암호화된 것으로 설정했기 때문입니다.

   ```ruby
   gitlab_rails['smtp_enable'] = true
   gitlab_rails['smtp_address'] = "smtp.mailgun.org" # or smtp.eu.mailgun.org
   gitlab_rails['smtp_port'] = 587
   gitlab_rails['smtp_authentication'] = "plain"
   gitlab_rails['smtp_enable_starttls_auto'] = true
   gitlab_rails['smtp_domain'] = "<mailgun domain>"
   ```

1. 파일을 저장하고 GitLab을 다시 구성합니다.

   ```shell
   sudo gitlab-ctl reconfigure
   ```

이제 이메일을 보낼 수 있어야 합니다. 구성이 작동하는지 테스트하려면:

1. Rails 콘솔을 입력합니다:

   ```shell
   sudo gitlab-rails console
   ```

1. 콘솔 프롬프트에서 다음 명령을 실행하여 GitLab이 테스트 이메일을 보내도록 합니다:

   ```ruby
   Notify.test_email('<email_address>', 'Message Subject', 'Message Body').deliver_now
   ```

이메일을 보낼 수 없으면 [SMTP 문제 해결 섹션](https://docs.gitlab.com/omnibus/settings/smtp/#troubleshooting)을 참조하세요.

#### 잠긴 계정에 대한 이메일 인증 필요 {#require-email-verification-for-locked-accounts}

계정 이메일 인증은 GitLab 계정 보안의 추가 계층을 제공합니다. 24시간 동안 3개 이상의 실패한 로그인 시도가 있을 때와 같은 특정 조건이 충족되면 계정이 잠깁니다.

전제 조건:

- 관리자여야 합니다.

잠긴 계정에 대한 이메일 인증을 요구하려면:

1. 오른쪽 위 모서리에서 **관리자**를 선택합니다.
1. 왼쪽 사이드바에서 **설정** > **일반**을 선택합니다.
1. **로그인 제한**을 확장합니다.
1. **잠긴 계정에 대한 이메일 인증** 확인란을 선택합니다.
1. **변경 사항 저장**을 선택합니다.

자세한 내용은 [계정 이메일 인증](../../security/email_verification.md)을 참조하세요.

#### S/MIME로 나가는 이메일 서명 {#sign-outgoing-email-with-smime}

GitLab에서 보낸 알림 이메일은 보안 강화를 위해 [S/MIME](https://en.wikipedia.org/wiki/S/MIME)로 서명할 수 있습니다.

하나의 키 및 인증서 파일 쌍을 제공해야 합니다:

- 두 파일 모두 PEM으로 인코딩되어야 합니다.
- GitLab이 사용자 개입 없이 읽을 수 있도록 키 파일의 암호를 해제해야 합니다.
- RSA 키만 지원됩니다.
- 선택사항. 각 서명에 포함할 인증서 기관(CA) 인증서 번들(PEM 인코딩)을 제공할 수 있습니다. 일반적으로 중간 CA입니다.

1. CA에서 인증서를 구입합니다.
1. `/etc/gitlab/gitlab.rb`을 편집하고 파일 경로를 조정합니다:

   ```ruby
   gitlab_rails['gitlab_email_smime_enabled'] = true
   gitlab_rails['gitlab_email_smime_key_file'] = '/etc/gitlab/ssl/gitlab_smime.key'
   gitlab_rails['gitlab_email_smime_cert_file'] = '/etc/gitlab/ssl/gitlab_smime.crt'
   ```

1. 파일을 저장하고 GitLab을 다시 구성합니다.

   ```shell
   sudo gitlab-ctl reconfigure
   ```

자세한 내용은 [S/MIME으로 나가는 이메일 서명](../../administration/smime_signing_email.md)을 참조하세요.

## 다음 단계 {#next-steps}

이 튜토리얼에서는 서버를 더욱 안전하게 설정하는 방법, GitLab을 설치하는 방법, 보안 표준을 충족하도록 GitLab을 구성하는 방법을 배웠습니다. GitLab을 보안으로 유지하기 위해 수행할 수 있는 [다른 단계](../../security/hardening_application_recommendations.md)는 다음과 같습니다:

- 새 사용자 계정을 비활성화합니다. 기본적으로 새 GitLab 인스턴스에는 새 사용자 계정이 활성화됩니다. GitLab 인스턴스를 공개하지 않으려면 새 사용자 계정을 비활성화해야 합니다.
- 특정 이메일 도메인을 사용하여 새 사용자 계정을 허용하거나 거부합니다.
- 새 사용자의 최소 비밀번호 길이 제한을 설정합니다.
- 모든 사용자에 대해 2단계 인증을 강제합니다.

GitLab 인스턴스를 강화하는 것 외에도 GitLab이 제공해야 하는 CI/CD 기능을 활용하기 위해 자신의 러너를 구성하거나 인스턴스를 적절히 백업하는 것과 같이 구성할 수 있는 많은 다른 항목이 있습니다.

[설치 후 수행할 단계](../../install/next_steps.md)에 대해 자세히 읽을 수 있습니다.
