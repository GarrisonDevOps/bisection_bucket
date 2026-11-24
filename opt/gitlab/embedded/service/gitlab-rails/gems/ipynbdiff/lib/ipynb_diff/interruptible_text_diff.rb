# frozen_string_literal: true

module IpynbDiff
  require 'diffy'

  DiffError = Class.new(StandardError)

  # A Diffy::Diff that kills the diff process when an exception (for example Timeout::Error)
  # interrupts the calling thread. Diffy uses Open3.capture3, which waits for the process to exit.
  class InterruptibleTextDiff < Diffy::Diff
    def initialize(string1, string2, options = {})
      super

      raise ArgumentError, 'Only the strings source is supported' unless self.options[:source] == 'strings'
      raise ArgumentError, 'Empty diffs must be allowed' unless self.options[:allow_empty_diff]
    end

    def diff
      @diff ||= begin
        @paths = [tempfile(string1), tempfile(string2)]

        output = run_diff
        output.force_encoding('ASCII-8BIT') unless output.valid_encoding?
        output
      end
    ensure
      @tempfiles&.each(&:unlink)
    end

    private

    def run_diff
      reader, writer = IO.pipe

      # Interrupts can only arrive during the read and the wait, so a running process is always killed and reaped.
      Thread.handle_interrupt(Object => :never) do
        pid = Process.spawn(diff_bin, *diff_options, *@paths, out: writer, err: File::NULL, pgroup: true)
        writer.close

        output, status = Thread.handle_interrupt(Object => :immediate) { [reader.read, Process.wait2(pid).last] }
        # diff exits with 0 (no differences) or 1 (differences). Other statuses and signals mean it failed.
        raise DiffError, "diff failed: #{status}" unless [0, 1].include?(status.exitstatus)

        output
      ensure
        stop(pid) if pid && !status
      end
    ensure
      reader&.close
      writer&.close
    end

    # Kills the whole process group, so a diff_bin wrapper cannot leave children running.
    def stop(pid)
      begin
        Process.kill(:KILL, -pid)
      rescue Errno::ESRCH, Errno::EPERM
        # No process of the group runs anymore. macOS returns EPERM when only the exited process is left.
      end

      Process.wait(pid)
    rescue Errno::ECHILD
      nil # The interrupt came after the wait had reaped the process
    end
  end
end
