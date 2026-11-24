---
stage: Verify
group: Runner Core
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/marketing/product-and-technical-marketing/technical-writing/#assignments>
title: 런북
description: "실행 가능한 런북, 자동화, 문제 해결 및 운영"
---

{{< details >}}

- 티어: Free, Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

런북은 시스템을 시작, 중지, 디버깅 또는 문제 해결하는 등 특정 프로세스를 수행하는 방법을 설명하는 문서화된 프로시저의 모음입니다.

[Jupyter Notebooks](https://jupyter.org/)와 [Rubix 라이브러리](https://github.com/Nurtch/rubix)를 사용하면 사용자가 자신의 실행 가능한 런북을 작성하기 시작할 수 있습니다.

역사적으로 런북은 조건이나 시스템에 따라 의사 결정 트리 또는 상세한 단계별 가이드 형태를 취했습니다.

현대적 구현은 "실행 가능한 런북"의 개념을 도입했으며, 잘 정의된 프로세스와 함께 운영자는 주어진 환경에 대해 사전 작성된 코드 블록 또는 데이터베이스 쿼리를 실행할 수 있습니다.

## 실행 가능한 런북 {#executable-runbooks}

GitLab Kubernetes 통합과 함께 제공되는 JupyterHub 앱은 이제 Nurtch Rubix 라이브러리를 포함하고 있으며, DevOps 런북을 만드는 간단한 방법을 제공합니다. 샘플 런북이 제공되어 일반적인 작업을 보여줍니다. Rubix는 일반적인 Kubernetes 및 AWS 워크플로우를 쉽게 만들 수 있지만, Rubix 없이 수동으로도 만들 수 있습니다.

<i class="fa-youtube-play" aria-hidden="true"></i> GitLab에서 이를 수행하는 방법에 대한 개요를 보려면 이 [영상](https://www.youtube.com/watch?v=Q_OqHIIUPjE)을 시청하세요!

## 요구사항 {#requirements}

실행 가능한 런북을 만들려면 다음이 필요합니다:

- **Kubernetes** \- Kubernetes 클러스터는 나머지 애플리케이션을 배포하기 위해 필요합니다. 시작하는 가장 간단한 방법은 [GitLab Kubernetes 에이전트](../../../clusters/agent/_index.md)를 사용하여 클러스터를 연결하는 것입니다.
- **Ingress** \- Ingress는 로드 밸런싱, SSL 종료 및 이름 기반 가상 호스팅을 제공할 수 있습니다. 애플리케이션의 웹 프록시로 작동합니다.
- **JupyterHub** - [JupyterHub](https://jupyterhub.readthedocs.io/en/stable/)는 팀 전체에서 노트북을 관리하기 위한 다중 사용자 서비스입니다. Jupyter Notebooks는 데이터 분석, 시각화 및 머신 러닝에 사용되는 웹 기반 대화형 프로그래밍 환경을 제공합니다.

## Nurtch {#nurtch}

Nurtch는 [Rubix 라이브러리](https://github.com/Nurtch/rubix)의 회사입니다. Rubix는 Jupyter Notebooks 내에서 일반적인 DevOps 작업을 쉽게 수행할 수 있게 해주는 오픈 소스 Python 라이브러리입니다. Cloudwatch 메트릭 도표 작성 및 ECS/Kubernetes 앱 롤링과 같은 작업이 몇 줄의 코드로 단순화됩니다. 자세한 내용은 [Nurtch 설명서](https://docs.nurtch.com/en/latest/)를 참조하세요.

## GitLab으로 실행 가능한 런북 구성 {#configure-an-executable-runbook-with-gitlab}

다음 단계별 가이드에 따라 이전에 설명한 컴포넌트와 사전 로드된 데모 런북을 사용하여 GitLab에서 실행 가능한 런북을 구성합니다.

1. [JupyterHub용 OAuth 애플리케이션](../../../../integration/oauth_provider.md)을 만듭니다.
1. [Helm을 사용하여 JupyterHub를 설치](https://zero-to-jupyterhub.readthedocs.io/en/latest/jupyterhub/installation.html)할 때 다음 값을 사용합니다:

   ```yaml
   #-----------------------------------------------------------------------------
   # The hub.config.GitLabOAuthenticator section must be customized!
   #-----------------------------------------------------------------------------

   hub:
     config:
       GitLabOAuthenticator:
         # Limit access to members of specific projects or groups or to specific users:
         # allowedGitlabGroups: [ "my-group-1", "my-group-2" ]
         # allowedProjectIds: [ 12345, 6789 ]
         # allowed_users: ["user-1", "user-2"]
         client_id: <Your OAuth Application ID>
         client_secret: <Your OAuth Application ID>
         enable_auth_state: true
         gitlab_url: https://gitlab.example.com
         oauth_callback_url: http://<Jupyter Hostname>/hub/oauth_callback
         scope:
           - read_user
           - read_api
           - openid
           - profile
           - email
       JupyterHub:
         authenticator_class: gitlab
      extraConfig:
        gitlab-config: |
           c.KubeSpawner.cmd = ['jupyter-labhub']
           c.GitLabOAuthenticator.scope = ['api read_repository write_repository']

           async def add_auth_env(spawner):
              '''
              Set user's id, login and access token on single user image to
              enable repository integration for JupyterHub.
              See: https://gitlab.com/gitlab-org/gitlab-foss/-/issues/47138#note_154294790
              '''
              auth_state = await spawner.user.get_auth_state()

              if not auth_state:
                 spawner.log.warning("No auth state for %s", spawner.user)
                 return

              spawner.environment['GITLAB_ACCESS_TOKEN'] = auth_state['access_token']
              spawner.environment['GITLAB_USER_EMAIL'] = auth_state['gitlab_user']['email']
              spawner.environment['GITLAB_USER_ID'] = str(auth_state['gitlab_user']['id'])
              spawner.environment['GITLAB_USER_LOGIN'] = auth_state['gitlab_user']['username']
              spawner.environment['GITLAB_USER_NAME'] = auth_state['gitlab_user']['name']

           c.KubeSpawner.pre_spawn_hook = add_auth_env

   singleuser:
      defaultUrl: "/lab"
      image:
         name: registry.gitlab.com/gitlab-org/jupyterhub-user-image
         tag: latest
      lifecycleHooks:
         postStart:
            exec:
            command:
               - "sh"
               - "-c"
               - >
                  git clone https://gitlab.com/gitlab-org/nurtch-demo.git DevOps-Runbook-Demo || true;
                  echo "https://oauth2:${GITLAB_ACCESS_TOKEN}@${GITLAB_HOST}" > ~/.git-credentials;
                  git config --global credential.helper store;
                  git config --global user.email "${GITLAB_USER_EMAIL}";
                  git config --global user.name "${GITLAB_USER_NAME}";
                  jupyter serverextension enable --py jupyterlab_git

   proxy:
      service:
         type: ClusterIP
   ```

1. JupyterHub가 성공적으로 설치된 후 브라우저에서 **Jupyter Hostname**을 엽니다. **GitLab으로 로그인** 버튼을 선택하여 JupyterHub에 로그인하고 서버를 시작합니다. 인증은 OAuth2를 사용하는 GitLab 인스턴스의 모든 사용자에 대해 활성화됩니다. 이 버튼은 JupyterHub가 GitLab 계정을 사용할 수 있도록 권한 부여를 요청하는 GitLab의 페이지로 리다이렉트됩니다.

   ![Jupyter가 GitLab 계정에 액세스할 수 있도록 권한을 요청하는 권한 부여 대화 상자](img/authorize_jupyter_v11_6.png)

1. **권한 부여**를 선택하면 GitLab이 JupyterHub 애플리케이션으로 리다이렉트됩니다.
1. **내 서버 시작**을 선택하여 몇 초 안에 서버를 시작합니다.
1. 런북의 GitLab 프로젝트 액세스를 구성하려면 데모 런북의 **설정** 섹션에서 [GitLab 액세스 토큰](../../../profile/personal_access_tokens.md)과 프로젝트 ID를 입력해야 합니다:

   1. 왼쪽 패널에 있는 **DevOps-Runbook-Demo** 폴더를 선택합니다.

      ![파일 브라우저에 DevOps-Runbook-Demo 폴더를 표시하는 JupyterHub Launcher](img/demo_runbook_v11_6.png)

   1. `Nurtch-DevOps-Demo.ipynb` 런북을 선택합니다.

      ![Nurtch-DevOps-Demo.ipynb 런북이 선택된 JupyterHub 파일 브라우저](img/sample_runbook_v11_6.png)

      Jupyter는 런북의 콘텐츠를 화면의 오른쪽에 표시합니다. **설정** 섹션에서 `PRIVATE_TOKEN`과 `PROJECT_ID`을 표시합니다. 다음과 같이 단일 따옴표를 유지하면서 이 값들을 입력합니다:

      ```sql
      PRIVATE_TOKEN = '<your_access_token>'
      PROJECT_ID = '1234567'
      ```

   1. 이 섹션의 마지막 줄에서 `VARIABLE_NAME`을 업데이트하여 액세스 토큰에 사용하는 변수의 이름과 일치하도록 합니다. 이 예에서 변수 이름은 `PRIVATE_TOKEN`입니다.

      ```sql
      VARIABLE_VALUE = project.variables.get('PRIVATE_TOKEN').value
      ```

1. 런북의 작동을 구성하려면 변수를 만들고 구성합니다. 이 예는 샘플 런북의 **노트북에서 SQL 쿼리 실행** 섹션을 사용하여 PostgreSQL 데이터베이스를 쿼리합니다. 다음 코드 블록의 처음 네 줄은 이 쿼리가 작동하는 데 필요한 변수를 정의합니다:

   ```sql
   %env DB_USER={project.variables.get('DB_USER').value}
   %env DB_PASSWORD={project.variables.get('DB_PASSWORD').value}
   %env DB_ENDPOINT={project.variables.get('DB_ENDPOINT').value}
   %env DB_NAME={project.variables.get('DB_NAME').value}
   ```

   1. **설정** > **CI/CD** > **변수**로 이동하여 프로젝트에서 변수를 만듭니다.

      ![마스킹된 값을 포함한 프로젝트의 CI/CD 변수 페이지에 추가된 데이터베이스 변수](img/gitlab_variables_v11_6.png)

   1. **변수 저장**을 선택합니다.

   1. Jupyter에서 **노트북에서 SQL 쿼리 실행** 제목을 선택한 다음 **실행**을 선택합니다. 결과는 다음과 같이 인라인으로 표시됩니다:

      ![데이터베이스 변수를 사용하여 PostgreSQL 쿼리를 실행하고 결과를 표시하는 Jupyter Notebook](img/postgres_query_v11_6.png)

쉘 스크립트 실행 또는 Kubernetes 클러스터와의 상호작용과 같은 다른 작업을 시도할 수 있습니다. 자세한 내용은 [Nurtch 설명서](https://docs.nurtch.com/en/latest/)를 참조하세요.
