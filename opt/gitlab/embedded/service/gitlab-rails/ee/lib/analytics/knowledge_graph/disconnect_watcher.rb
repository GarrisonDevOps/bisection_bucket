# frozen_string_literal: true

module Analytics
  module KnowledgeGraph
    # Puma has read the whole request, so a readable socket at EOF means the client left.
    class DisconnectWatcher
      Watch = Struct.new(:socket, :call, :cancelled)
      MUTEX = Mutex.new

      class << self
        def watch(socket, call)
          return unless socket.respond_to?(:recv_nonblock)

          instance.add(Watch.new(socket, call))
        end

        def unwatch(watch)
          MUTEX.synchronize { @instance }&.remove(watch) if watch
        end

        def instance
          MUTEX.synchronize do
            @instance = nil unless @instance&.alive?
            @instance ||= new
          end
        end
      end

      def initialize
        @pid = Process.pid
        @mutex = Mutex.new
        @watches = {}
        @wakeup_reader, @wakeup_writer = IO.pipe
        @thread = Thread.new { run }
        @thread.name = 'orbit-disconnect-watcher'
      end

      def add(watch)
        @mutex.synchronize { @watches[watch.socket] = watch }
        wake
        watch
      end

      def remove(watch)
        @mutex.synchronize { @watches.delete(watch.socket) if @watches[watch.socket].equal?(watch) }
        wake
      end

      def alive?
        @pid == Process.pid && @thread.alive?
      end

      private

      def run
        loop do
          sockets = @mutex.synchronize { @watches.keys }
          ready, = IO.select(sockets + [@wakeup_reader])
          ready.each { |io| io == @wakeup_reader ? drain_wakeups : check(io) }
        rescue IOError, SystemCallError
          prune_closed
        rescue StandardError => e
          ::Gitlab::ErrorTracking.track_exception(e)
          prune_closed
        end
      end

      def check(socket)
        peeked = socket.recv_nonblock(1, Socket::MSG_PEEK, exception: false)
        return if peeked == :wait_readable

        watch = @mutex.synchronize { @watches.delete(socket) }
        cancel(watch) if peeked.nil? || peeked.empty?
      rescue IOError, SystemCallError
        cancel(@mutex.synchronize { @watches.delete(socket) })
      end

      def cancel(watch)
        return unless watch

        watch.cancelled = true
        watch.call.cancel
      end

      def prune_closed
        @mutex.synchronize { @watches.delete_if { |socket, _| socket.closed? } }
      end

      def wake
        @wakeup_writer.write_nonblock('.', exception: false)
      end

      def drain_wakeups
        @wakeup_reader.read_nonblock(1024, exception: false)
      end
    end
  end
end
