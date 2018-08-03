require 'synapse/config_generator/base'

require 'fileutils'
require 'json'
require 'socket'
require 'digest/sha1'
require 'set'
require 'hashdiff'
require 'resolv'
require 'yaml'

class Synapse::ConfigGenerator
  class Envoy < BaseGenerator
    include Synapse::Logging

    NAME = 'envoy'.freeze

    # These come from documentation for Envoy (1.6)

    SECTION_FIELDS = [
      'listeners' => {
      },
      'clusters' => {
      },
      'admin' => [
        'access_log_path',
      ],
    ].freeze

    DEFAULT_STATE_FILE_TTL = (60 * 60 * 24).freeze #24 hours
    STATE_FILE_UPDATE_INTERVAL = 60.freeze # iterations; not a unit of time
    DEFAULT_BIND_ADDRESS = '127.0.0.1'

    attr_reader :state_cache

    def initialize(opts)
      super(opts)

      #%w{global defaults}.each do |req|
      # raise ArgumentError, "Envoy requires a #{req} section" if !opts.has_key?(req)
     # end

      # Default opts
      @opts['do_writes'] = true unless @opts.key?('do_writes')
      @opts['do_reloads'] = true unless @opts.key?('do_reloads')

      # how to restart envoy
      @restart_interval = @opts.fetch('restart_interval', 2).to_i
      @restart_jitter = @opts.fetch('restart_jitter', 0).to_f
      @restart_required = true

      # TODO HERE: PUT TOGETHER ALL THE HOT RELOAD CONFIGURATIONS
      @reload_command = ""

      # virtual clock bookkeeping for controlling how often envoy restarts
      @time = 0
      @next_restart = @time

      @admin_configs = {
        'access_log_path' => @opts.fetch('admin_log_path', '/dev/null'),
        'admin_socket_addr' => @opts.fetch('admin_socket_addr', '127.0.0.1'),
        'admin_port_value' => @opts.fetch('admin_port_value', '8001'),
      }

      # Configurations for Envoy's stats reporter
      # https://www.envoyproxy.io/docs/envoy/latest/intro/arch_overview/statistics
      # stats_address must be an IP address.
      @stats_configs = {
        'stats_address' => @opts.fetch('stats_address', nil),
        'stats_port_value' => @opts.fetch('stats_port_value', '8125'),
      }
      # a place to store the parsed envoy config from each watcher
      # This is the config stanza in `/etc/synapse.d/<service.yaml>`, e.g.
      # envoy:
      #   bind_address: "127.0.103.1"
      #   port: 9090
      #   server_options: "check"
      #   listen:
      #    - "mode tcp"
      @watcher_configs = {}

      # a place to store generated listeners and clusters stanzas
      @listeners_cache = {}
      @clusters_cache = {}
      @watcher_revisions = {}
    end

    def normalize_watcher_provided_config(service_watcher_name, service_watcher_config)
      service_watcher_config = super(service_watcher_name, service_watcher_config)

      defaults = {
      }

      unless service_watcher_config.include?('port')
        log.warn "synapse: service #{service_watcher_name}: Envoy config does not include a port; only cluster sections for the service will be created. You will need to define a listener section manually."
      end

      defaults.merge(service_watcher_config)
    end

    # split the envoy config in each watcher into fields applicable in
    # frontend and backend sections
    def parse_watcher_config(watcher)
    end

    # TODO: Verify if the restart required is needed.
    def tick(watchers)
      if (@time % STATE_FILE_UPDATE_INTERVAL) == 0
        update_state_file(watchers)
      end

      @time += 1

      # We potentially have to restart if the restart was rate limited
      # in the original call to update_config
      restart if opts['do_reloads'] && @restart_required
    end

    def update_config(watchers)
      @restart_required = true
      # generate a new config
      new_config = generate_config(watchers)

      # if we write config files, lets do that and then possibly restart
      if opts['do_writes']
        write_config(new_config)
        restart if opts['do_reloads'] && @restart_required
      end
    end

    def update_state_file(watchers)
      #@state_cache.update_state_file(watchers)
    end

    def generate_admin_config
      admin_config = {
        'access_log_path' => @admin_configs['access_log_path'],
        'address' => {
          'socket_address' => {
            'address' => @admin_configs['admin_socket_addr'],
            'port_value' => @admin_configs['admin_port_value'],
          },
        },
      }
      return admin_config
    end

    def generate_stats_config
      # Envoy expects an IP address for the stats sink host, so
      # we need to do a DNS lookup if necessary.
      config_addr = @stats_configs['stats_address']

      if not config_addr
        return {}
      end

      if config_addr =~ Resolv::IPv4::Regex
        stats_addr = config_addr
      else
        # Assume it's still a valid string address that requires
        # a lookup.
        stats_addr = Resolv::DNS.new.getaddress(config_addr).to_s
      end

      stats_config = {
        'stats_sinks' => [
          {
            'name' => 'envoy.statsd',
            'config' => {
              'address' => {
                'socket_address' => {
                  'address' => stats_addr,
                  'port_value' => @stats_configs['stats_port_value'],
                },
              },
            },
          },
        ],
      }
      return stats_config
    end

    def generate_base_config
      base_config = {
        'static_resources' => {
          'listeners' => [],
          'clusters' => [],
        },
        'admin' => generate_admin_config,
      }

      base_config = base_config.merge(generate_stats_config)

      return base_config
    end

    def generate_listeners_stanza(watcher, config)
      watcher_config = watcher.config_for_generator[name]

      unless watcher_config.has_key?("port")
        log.debug("synapse: not generating listener stanza for watcher #{watcher.name} because it has no port defined")
        return {}
      else
        port = watcher_config['port']
      end

      bind_address = (
        watcher_config['bind_address'] || DEFAULT_BIND_ADDRESS
      )
      cluster_name = watcher_config.fetch('backend_name', watcher.name)

      listener_config = watcher_config.fetch('listener', {})
      filter_configs = {}

      if not listener_config.empty?
        filter_list = listener_config.fetch('filters', [])

        filter_list.each do | filter |
          filter.each do |filter_name, filter_config|
            filter_configs[filter_name] = filter_config
          end
        end
      end

      default_tcp_config = {
        'stat_prefix' => 'ingress_tcp',
        'max_connect_attempts' => 3,
        'idle_timeout' => '60s',
      }

      tcp_config = default_tcp_config.merge(filter_configs.fetch('tcp', {}))

      # Explicit null value passed indicating no port needed
      # For example if the bind_address is a unix port
      # TODO: FIGURE OUT WHAT THIS NEEDS TO BE TO SUPPORT UNIX CONFIGURATION
      bind_port = port.nil? ? '' : "#{port}"

      stanza = {
        'address' => {
          'socket_address' => {
            'address' => bind_address,
            'port_value' => bind_port
          }
        },
        'filter_chains' => [
          'filters' => [
            {
              'name' => 'envoy.tcp_proxy',
              'config' => {
                'stat_prefix' => tcp_config.fetch('stat_prefix', 'ingress_tcp'),
                'max_connect_attempts' => tcp_config.fetch('max_connect_attempts', 3),
                'idle_timeout' => tcp_config.fetch('idle_timeout', '60s'),
                'cluster' => cluster_name,
                'access_log' => [
                  'name' => 'envoy.file_access_log',
                  'config' => {
                    'path' => '/var/log/envoy.log',
                  }
                ]
              }
            }
          ]
        ]
      }

      return stanza
    end

    def generate_clusters_stanza(watcher, config)
      if watcher.backends.empty?
        log.debug "synapse: no backends found for watcher #{watcher.name}"
      end

      watcher_config = watcher.config_for_generator[name]

      cluster_config = watcher_config.fetch('cluster', {})

      host_list = []
      watcher.backends.each do | backend |
        backend_entry = {}
        backend_entry['socket_address'] = {
          'address' => backend['host'],
          'port_value' => backend['port'],
        }
        host_list << backend_entry
      end

      # Write the cluster stanza for Envoy now
      stanza = {
        'name' => watcher.name,
        'connect_timeout' => cluster_config.fetch('connect_timeout', '1s'),
        'type' => cluster_config.fetch('type', 'strict_dns'),
        'lb_policy' => cluster_config.fetch('lb_policy', 'least_request'),
        'hosts' => host_list,
        'health_checks' => [generate_health_check_config(cluster_config)],
      }
      return stanza
    end

    def generate_health_check_config(cluster_config)
      # Only possible to generate TCP health checks right now.
      health_check_config = cluster_config.fetch('health_check', {})
      return {
          'timeout' => health_check_config.fetch('timeout', '1s'),
          'interval' => health_check_config.fetch('interval', '2s'),
          'unhealthy_threshold' => health_check_config.fetch('unhealthy_threshold', 2),
          'healthy_threshold' => health_check_config.fetch('healthy_threshold', 3),
          'tcp_health_check' => {
            'send' => nil,
            'receive' => nil,
          },
      }
    end

    # Generate a new Envoy config based on the state of the watchers
    def generate_config(watchers)
      new_config = generate_base_config

      watchers.each do |watcher|
        watcher_config = watcher.config_for_generator[name]
        next if watcher_config.nil? || watcher_config.empty? || watcher_config['disabled']
        @watcher_configs[watcher.name] = parse_watcher_config(watcher)
        #if watcher_config is changed, trigger restart
        #config_diff = HashDiff.diff(@state_cache.config_for_generator(watcher.name, watcher_config))
        #if !config_diff.empty?
          #log.info "synapse: restart required because config_for_generator changed. before: #{@state_cache.config_for_generator(watcher.name)}, after: #{watcher_config}"
          #@restart_required = true
  #      end

        regenerate = watcher.revision != @watcher_revisions[watcher.name] ||
                     @listeners_cache[watcher.name].nil? ||
                     @clusters_cache[watcher.name].nil?

        if regenerate
          @listeners_cache[watcher.name] = generate_listeners_stanza(watcher, @watcher_configs[watcher.name])
          @clusters_cache[watcher.name] = generate_clusters_stanza(watcher, @watcher_configs[watcher.name])
          @watcher_revisions[watcher.name] = watcher.revision
        end

      end

      @listeners_cache.each do | watcher_name, listener_stanza |
        new_config['static_resources']['listeners'] << listener_stanza
      end
      # Write all the clusters
      @clusters_cache.each do | watcher_name, cluster_stanza |
        new_config['static_resources']['clusters'] << cluster_stanza
      end
      return new_config
    end

    def write_config(new_config)
      # new_config is giant hash
      begin
        old_config = File.read(opts['config_file_path'])
      rescue Errno::ENOENT => e
        log.error "synapse: could not open Envoy config file at #{opts['config_file_path']}"
        old_config = ""
      end

      if old_config == new_config
        return false
      else
        tmp_file_path = "#{opts['config_file_path']}.tmp"
        # Write YAML out from new_config hash
        File.write(tmp_file_path, new_config.to_yaml)
        FileUtils.mv(tmp_file_path, opts['config_file_path'])
        return true
      end
    end

    # used to build unique, consistent envoy cluster names
    def construct_name(backend)
      name = "#{backend['host']}:#{backend['port']}"
      if backend['name'] && !backend['name'].empty?
        name = "#{backend['name']}_#{name}"
      end
      return name
    end

    # restarts Envoy if the time is right
    def restart
      if @time < @next_restart
        log.info "synapse: at time #{@time} waiting until #{@next_restart} to restart"
        return
      end

      @next_restart = @time + @restart_interval
      @next_restart += rand(@restart_jitter * @restart_interval + 1)

      # do the actual restart
      res = `#{opts['reload_command']}`.chomp
      unless $?.success?
        log.error "failed to reload envoy via #{opts['reload_command']}: #{res}"
        return
      end
      log.info "synapse: restarted envoy"

      @restart_required = false
    end


    ######################################
    # methods for managing the state file
    ######################################
    class EnvoyState
      include Synapse::Logging
      # TODO: enable version in the Envoy Cache File
      KEY_WATCHER_CONFIG_FOR_GENERATOR = "watcher_config_for_generator"
      NON_BACKENDS_KEYS = [KEY_WATCHER_CONFIG_FOR_GENERATOR]

      # Params:
      # +state_file_path+:: path to write state file to
      # +state_file_ttl+:: ttl for state file
      # +envoy+:: Envoy config generator
      def initialize(state_file_path, state_file_ttl, envoy)
        @state_file_path = state_file_path
        @state_file_ttl = state_file_ttl
        @envoy = envoy
      end

      def backends(watcher_name)
        if seen.key?(watcher_name)
          seen[watcher-name]
        end
      end
    end
  end
end
