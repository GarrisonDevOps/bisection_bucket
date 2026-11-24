---
stage: AI Platform
group: AI Core Infra
info: To determine the technical writer assigned to the Stage/Group, see <https://handbook.gitlab.com/handbook/marketing/product-and-technical-marketing/technical-writing/#assignments>
title: Semantic Code Search
---

## Overview

Semantic Code Search is the first feature offered under Semantic Search. It enables Duo Chat and other AI features to find relevant code snippets from a repository. The feature is available as an [MCP tool (`semantic_code_search`)](../../../user/model_context_protocol/mcp_server_tools.md#semantic_search) that can be used by GitLab Duo Agent Platform and other AI platforms.

## Architecture

### Semantic Code Search embedding model

The Semantic Code Search embedding model depends on the GitLab instance.

For SaaS, Dedicated, and GitLab Self-Managed instances without Duo Self-hosted, the model used for embeddings generation is
`text-embedding-005` provided by Gemini Enterprise Agent Platform.

For GitLab Self-Managed instances with Duo Self-hosted, administrators must select their own Self-hosted embedding model.

### Indexing workflow

#### Initial indexing

When the Semantic Code Search tool is invoked for a project that hasn't been indexed yet:

1. **Repository record creation**: An `Ai::ActiveContext::Code::Repository` record is created with `pending` state
1. **Index worker**: The `Ai::ActiveContext::Code::RepositoryIndexWorker` processes the `pending` repository
1. **Initial indexing**:
   1. The `Ai::ActiveContext::Code::InitialIndexingService` calls the `Ai::ActiveContext::Code::Indexer`
   1. The `Ai::ActiveContext::Code::Indexer` runs the [`gitlab-elasticsearch-indexer`](#gitlab-elasticsearch-indexer) to fetch the repository's files from Gitaly, chunk the code, and index the chunks in the vector store
   1. The `Ai::ActiveContext::Code::InitialIndexingService` enqueues the references/IDs of the indexed content for embeddings generation
1. **Async processing**: Queued content references are picked up for embeddings generation through the asynchronous `Ai::ActiveContext::BulkProcessWorker`.
1. **Tool not available**: The user is notified that indexing is in progress and should try again in a few minutes.
1. **Ready check**: The `Ai::ActiveContext::Code::MarkRepositoryAsReadyEventWorker` runs on a 10-minute cron schedule (through `Ai::ActiveContext::Code::SchedulingService`) and checks if all embeddings have been generated. Once all embeddings are ready, it marks the repository as `ready`
1. **Available for queries**: The next time the tool is invoked, the repository is ready and can be used for semantic search queries

If initial indexing fails, the `Ai::ActiveContext::Code::InitialIndexingService` updates the repository state:

- On the first failure, the state changes to `pending_retry` and `last_commit` is cleared, so the retry runs a full initial index.
- Every 30 minutes, the `retry_repository` task of `Ai::ActiveContext::Code::SchedulingService`
  enqueues each `pending_retry` repository to the `Ai::ActiveContext::Code::RepositoryIndexWorker`.
- If the retry also fails, the state changes to `failed`. GitLab does not retry `failed` repositories automatically.
  [Issue 629396](https://gitlab.com/gitlab-org/gitlab/-/work_items/629396) proposes retrying them.

#### Incremental indexing

When code is merged into the default branch:

1. **Push event**: A push event triggers the incremental indexing process through the `Git::BranchPushService`
1. **Index worker**: The `Ai::ActiveContext::Code::RepositoryIndexWorker` processes the `ready` ActiveContext repository
1. **Incremental Indexing** - only the changed files are processed
   1. The `Ai::ActiveContext::Code::IncrementalIndexingService` calls the `Ai::ActiveContext::Code::Indexer`
   1. The `Ai::ActiveContext::Code::Indexer` runs the [`gitlab-elasticsearch-indexer`](#gitlab-elasticsearch-indexer) to fetch the changed files from Gitaly, chunk the code, and index the chunks in the vector store. It also deletes orphaned data from the vector store.
   1. The `Ai::ActiveContext::Code::IncrementalIndexingService` enqueues the references/IDs of the indexed content for embeddings generation
1. **Async processing**: Queued content references are picked up for embeddings generation through the asynchronous `Ai::ActiveContext::BulkProcessWorker`.

### Deletion workflow

When a namespace is no longer eligible for indexing, `Ai::ActiveContext::Code::ProcessInvalidEnabledNamespaceEventWorker` picks it up and deletes the `Ai::ActiveContext::Code::EnabledNamespace` record.

When a repository is no longer eligible for indexing, `Ai::ActiveContext::Code::MarkRepositoryAsPendingDeletionEventWorker` marks it as `pending_delete`. The `Ai::ActiveContext::Code::RepositoryIndexWorker` then processes the repository and calls the [`gitlab-elasticsearch-indexer`](#gitlab-elasticsearch-indexer) to delete the project's documents from the vector store and delete the repository record.

### `gitlab-elasticsearch-indexer`

The [`gitlab-elasticsearch-indexer`](https://gitlab.com/gitlab-org/gitlab-elasticsearch-indexer) Go project handles:

- fetching the repository's files from Gitaly
- chunking the files
- indexing the chunked content on the vector store
- deleting orphaned data
- deleting all data for a project

**Chunking**

The `gitlab-elasticsearch-indexer` makes use of the [`gitlab-code-parser`](https://gitlab.com/gitlab-org/rust/gitlab-code-parser) library to split the code into logic chunks.

The chunking process uses a two-stage approach:

1. _AST-aware chunking_: The code chunker parses each file and identifies logical split points (function definitions, class definitions, and similar constructs)
1. _Size-based fallback_: If no AST split points are available, the chunker falls back to splitting on line boundaries while respecting a maximum byte size

This approach ensures chunks are semantically meaningful while staying within size limits for embedding generation.

### Queues

Semantic Code Search uses two [queues](active_context.md#queues):

- `Ai::ActiveContext::Queues::Code`: Generates embeddings for the current indexing embedding model.
  Passes `current_model_only: true` to the preprocessors.
- `Ai::ActiveContext::Queues::CodeBackfill`: Generates embeddings for the next indexing embedding model
  during [model switching](active_context.md#model-switching).
  Passes `next_model_only: true` to the preprocessors.

Both queues read `number_of_shards` and `shard_limit` from the collection record
(`queue_shard_count` and `queue_shard_limit`), with defaults of `1` and `1000`.

Throughput is limited on instances other than GitLab.com that use a GitLab-managed embedding model.
When throughput is limited, the queue uses one shard,
and `shard_limit` is capped at 20 times the embedding request batch size, which is about 20 embedding requests a minute.

### Namespace eligibility

Not all namespaces are eligible for Semantic Code Search. Eligibility is managed through two workers:

**`Ai::ActiveContext::Code::CreateEnabledNamespaceEventWorker`** (runs daily through `Ai::ActiveContext::Code::SchedulingService`)

- Identifies and enables eligible namespaces
- Creates `Ai::ActiveContext::Code::EnabledNamespace` records for qualifying namespaces

**On GitLab.com**, a namespace is eligible if:

- AI features are enabled in the namespace settings
- The namespace has a supported AI plan (Premium or higher)
- The subscription is not expired

**On GitLab Self-Managed instances**, all top-level group namespaces are eligible if:

- Instance-level AI beta features are enabled (`instance_level_ai_beta_features_enabled`)
- AI features are available in the license

**`Ai::ActiveContext::Code::MarkRepositoryAsPendingDeletionEventWorker`** marks repositories for deletion when they no longer meet eligibility criteria.

**`Ai::ActiveContext::Code::ProcessInvalidEnabledNamespaceEventWorker`** cleans up `Ai::ActiveContext::Code::EnabledNamespace` records for namespaces that no longer meet eligibility criteria.

### Supported file types

Semantic Code Search indexes all files in a repository. Currently, results are post-filtered to exclude files matching the project's exclusion rules. Future versions will stop indexing excluded files entirely for improved efficiency.

### MCP implementation

For more information about GitLab MCP implementation and available clients, see the [GitLab MCP documentation](../../../user/gitlab_duo/model_context_protocol/mcp_clients.md) and the [runbook](https://gitlab.com/gitlab-com/runbooks/-/tree/master/docs/ai-active-context).

Currently, the Semantic Code Search tool is available in IDEs when GitLab MCP is configured. With the rollout of the `mcp_client` feature flag, it will be available on the web.

## Enabling Semantic Code Search

### Prerequisites

- `ActiveContext` gem configured in `config/initializers/active_context.rb`:

  ```ruby
  ActiveContext.configure do |config|
    config.enabled = true
    config.indexing_enabled = true
    config.logger = ::Gitlab::ActiveContext::Logger.build

    config.queue_classes = []
    if Gitlab.ee?
      config.queue_classes.concat([
        ::Ai::ActiveContext::Queues::Code,
        ::Ai::ActiveContext::Queues::CodeBackfill
      ])
    end
  end
  ```

- Your GDK is [prepared for GitLab Duo features](../_index.md#prepare-your-gdk), with the `gitlab-duo` root namespace.
- [Beta experiment features setting enabled](../../../user/gitlab_duo/turn_on_off.md#turn-on-beta-and-experimental-features).
- A vector store running in your GDK: [Elasticsearch or OpenSearch](https://gitlab-org.gitlab.io/gitlab-development-kit/howto/elasticsearch/), or [PostgreSQL with `pgvector`](https://gitlab-org.gitlab.io/gitlab-development-kit/howto/pgvector/).
- Embeddings generation:
  - [AI Gateway configured](../duo_agent_platform.md)
  - [Gemini Enterprise Agent Platform](https://docs.cloud.google.com/gemini-enterprise-agent-platform/models/embeddings) credentials configured
- `gitlab-elasticsearch-indexer` built in your GDK at the version in [`GITLAB_ELASTICSEARCH_INDEXER_VERSION`](https://gitlab.com/gitlab-org/gitlab/-/blob/master/GITLAB_ELASTICSEARCH_INDEXER_VERSION).
  The GDK builds the indexer in the `gitlab-elasticsearch-indexer` directory of your GDK root.

### Verifying prerequisites

#### Embeddings generation

Test that embeddings generation is configured:

```ruby
model_metadata = {
  model_ref: 'text_embedding_005_vertex',
  field: 'test_field_v1',
  dimensions: 768
}
::Ai::ActiveContext::Embeddings::ModelFactory
  .for(model_metadata)
  .generate_embeddings('test', user: User.first)
```

This should return a vector.

### Setting up Semantic Code Search in the GDK

Use Rake tasks to set up Semantic Code Search and index a project in your GDK.
The tasks support only a GDK that [simulates a SaaS instance](../../ee_features.md#simulate-a-saas-instance),
and require advanced search configured with Elasticsearch or OpenSearch.

#### Setup and migrations

To set up the vector store connection, run the Active Context migrations, and enable the feature flags, run:

```shell
GITLAB_SIMULATE_SAAS=1 bundle exec rake gitlab:semantic_search:setup
```

The task:

- Clears the self-hosted AI Gateway URL, if set, so the migrations can use GitLab-managed embedding models.
- Uses the active connection, or creates and activates a connection to the advanced search cluster.
  For other connection types, [create a connection](_index.md#creating-a-connection) before you run the task.
- Runs the migrations until they complete, and checks that the code collection has embedding models.
- Enables the `semantic_code_search_saas_ga` feature flag.

Optional. To verify that the migrations created the index, do one of the following:

- In the Kibana Dev Tools console (`http://localhost:5601/app/dev_tools#/console`), run:

  ```console
  GET gitlab_active_context_code
  ```

- In your browser, go to `http://localhost:9200/gitlab_active_context_code`, or run:

  ```shell
  curl "http://localhost:9200/gitlab_active_context_code"
  ```

If the migrations succeeded, the response contains the index information.

#### Indexing a project

To index a project and generate its embeddings, run:

```shell
GITLAB_SIMULATE_SAAS=1 DEVELOPMENT_AI_GATEWAY_URL=http://gdk.test:5052 \
bundle exec rake "gitlab:semantic_search:setup:index_project[<project_full_path>]"
```

If you omit `<project_full_path>`, the task indexes `gitlab-duo/ai-gateway`.
All Active Context queues must be empty before you run the task.

The task marks the root namespace as enabled and resets the repository record, so the project always gets a full initial index.
It then indexes the repository, generates the embeddings, and marks the repository as `ready`.

To verify the setup, [run a semantic search](#using-semantic-code-search) on the indexed project.

### Testing embedding models on GitLab Self-Managed

The connection, migrations, and indexed project that the [SaaS Rake tasks](#setting-up-semantic-code-search-in-the-gdk)
set up remain valid if you switch your GDK to GitLab Self-Managed.

To make [self-hosted embedding models](_index.md#semantic-search-for-duo-self-hosted) work with this setup:

- Set the self-hosted AI Gateway URL:

  ```ruby
  ApplicationSetting.current.update!(ai_gateway_url: 'http://gdk.test:5052')
  ```

- If you set the self-hosted AI Gateway URL but keep `text-embedding-005`,
  the embedding model metadata requires a `model_type`.
  To set the `model_type`:

  ```ruby
  collection = ::Ai::ActiveContext::Collections::Code.collection_record
  embedding_model = collection.current_indexing_embedding_model.merge(model_type: 'gitlab_managed')

  collection.update_metadata!(
    'current_indexing_embedding_model' => embedding_model,
    'search_embedding_model' => embedding_model
  )
  ```

## Disabling Semantic Code Search

> [!warning]
> Disabling semantic code search can cause long database locks if there are many repository records to delete.
> Use with caution on production environments. Upcoming work will allow disabling safely.
> See [issue 582787](https://gitlab.com/gitlab-org/gitlab/-/issues/582787).

Delete the index and collection record:

```ruby
ActiveContext.adapter.executor.drop_collection(:code)
```

Delete the connection and associated records:

```ruby
::Ai::ActiveContext::Connection.active.destroy!
```

## Indexing with `gitlab-elasticsearch-indexer` directly

Use this procedure only to test changes to the [`gitlab-elasticsearch-indexer`](#gitlab-elasticsearch-indexer).
To index a repository without Rails, build the indexer and run it in `chunk` mode:

1. Get the repository relative path from the Rails console:

   ```ruby
   Project.find_by_full_path('<project_full_path>').repository.relative_path
   # => "@hashed/6b/86/6b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e52ddb7875b4b.git"
   ```

1. From your GDK root directory, build and run the indexer:

   ```shell
   cd gitlab-elasticsearch-indexer
   make && \
   GITLAB_INDEXER_MODE=chunk \
   GITLAB_INDEXER_DEBUG_LOGGING=1 \
   ./bin/gitlab-elasticsearch-indexer \
   -adapter "elasticsearch" \
   -connection '{"url": ["http://localhost:9200"]}' \
   -options '{
     "timeout": "30m",
     "chunk_size": 1000,
     "gitaly_batch_size": 1000,
     "from_sha": "",
     "to_sha": "",
     "project_id": <project_id>,
     "partition_name": "gitlab_active_context_code",
     "partition_number": 0,
     "gitaly_config": {
       "address": "<gitaly_address>",
       "storage": "default",
       "relative_path": "<relative_path>",
       "project_path": "<project_full_path>"
     }
   }'
   ```

   For `<gitaly_address>`, use the `gitaly_address` of the `default` storage in `config/gitlab.yml`,
   for example `unix:/path/to/gdk/praefect.socket`.

## Setting up MCP locally

To set up the MCP server locally for development and testing, see the [MCP server development guide](../../duo_agent_platform/mcp/_index.md).

> [!note]
> Ask for the `semantic_code_search` tool in your prompt to ensure the tool is used.

## Using Semantic Code Search

To invoke semantic search from your console, use the `Ai::ActiveContext::Queries::Code` class:

```ruby
# Check if semantic code search is available
Ai::ActiveContext::Queries::Code.available?

# Perform a semantic search
result = Ai::ActiveContext::Queries::Code.new(
  search_term: "user authentication logic",
  user: current_user
).filter(
  project_or_id: project.id,
  path: "app/controllers/",  # Optional: filter by directory
  knn_count: 10,             # Number of vectors to compare
  limit: 10                  # Number of results to return
)
```

## Troubleshooting

### `All ActiveContext queues must be empty before indexing` error

The `gitlab:semantic_search:setup:index_project` task fails with this error when an Active Context queue
contains references. The error message lists the non-empty queues.

A failed run, for example one that fails with `The code queue did not shrink`,
can leave references in `Ai::ActiveContext::Queues::Code`, or move them to the retry queues.

To resolve this issue, do one of the following:

- If [embeddings generation](#embeddings-generation) works, process the queues:

  ```ruby
  ActiveContext.execute_all_queues!
  Ai::ActiveContext::Queues::Code.queue_size
  ```

  Each call processes one batch per queue shard, so repeat the call until `queue_size` returns `0`.
  If the size stops decreasing, see [Embeddings queue does not shrink](#embeddings-queue-does-not-shrink).

  This method does not process items in the retry queues until their retry delay passes,
  and never processes the dead queue. To empty those queues, clear them.

- Clear each non-empty queue:

  ```ruby
  Ai::ActiveContext::Queues::Code.clear_tracking!
  ActiveContext::Queues.retry_chain.each(&:clear_tracking!)
  ActiveContext::DeadQueue.clear_tracking!
  ```

### Embeddings queue does not shrink

`ActiveContext.execute_all_queues!` does not reduce the size of `Ai::ActiveContext::Queues::Code`.

This issue usually means that GitLab cannot generate embeddings through AI Gateway.
To confirm, run the [embeddings generation check](#embeddings-generation).
If the check returns a `Forbidden by auth provider` error, see the next section.
For other errors, check `log/active_context.log`.

If you need help, ask in the `#f_semantic-code-search` or `#f_ai-gateway` Slack channels.

### `Forbidden by auth provider` error

This error occurs when AI Gateway cannot access Google Vertex AI.

To resolve this issue:

1. Verify that your local GitLab instance connects to your local AI Gateway.
1. Verify that your local AI Gateway has credentials with access to Google Vertex AI.
1. Check the AI Gateway logs for authentication errors.

For more information, see the [AI Gateway authentication and authorization documentation](https://gitlab.com/gitlab-org/modelops/applied-ml/code-suggestions/ai-assist/-/blob/main/docs/auth.md).

### Repository is in the `failed` state

GitLab does not retry repositories in the `failed` state automatically.
To retry initial indexing, reset the repository to `pending`:

```ruby
repository.update!(state: :pending, last_commit: nil, metadata: {})
```
