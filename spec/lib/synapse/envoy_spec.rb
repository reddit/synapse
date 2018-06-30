require 'spec_helper'
require 'synapse/config_generator/envoy'

class MockWatcher; end;

describe Synapse::ConfigGenerator::Envoy do
  subject { Synapse::ConfigGenerator::Envoy.new(config['envoy']) }

  let(:mockwatcher) do
    mockWatcher = double(Synapse::ServiceWatcher)
    allow(mockWatcher).to receive(:name).and_return('example_service')
    backends = [{ 'host' => 'somehost', 'port' => 5555}]
    allow(mockWatcher).to receive(:backends).and_return(backends)
    allow(mockWatcher).to receive(:config_for_generator).and_return({
      'envoy' => {},
    })
    allow(mockWatcher).to receive(:revision).and_return(1)
    mockWatcher
  end

  let(:mockwatcher_frontend) do
    mockWatcher = double(Synapse::ServiceWatcher)
    allow(mockWatcher).to receive(:name).and_return('example_service4')
    allow(mockWatcher).to receive(:config_for_generator).and_return({
      'envoy' => {'port' => 9090}
    })
    allow(mockWatcher).to receive(:revision).and_return(1)
    mockWatcher
  end

  let(:mockwatcher_frontend_with_bind_address) do
    mockWatcher = double(Synapse::ServiceWatcher)
    allow(mockWatcher).to receive(:name).and_return('example_service5')
    backends = [
      { 'host' => 'somehost', 'port' => 5555},
      { 'host' => 'somehost2','port' => 5555},
    ]
    allow(mockWatcher).to receive(:backends).and_return(backends)
    allow(mockWatcher).to receive(:config_for_generator).and_return({
      'envoy' => {'port' => 9090, 'bind_address' => "127.0.0.3"}
    })
    allow(mockWatcher).to receive(:revision).and_return(1)
    mockWatcher
  end

  describe '#initialize' do
    it 'succeeds on minimal config' do
      conf = {
        'global' => [],
        'defaults' => [],
        'do_writes' => false,
        'do_reloads' => false,
        'do_socket' => false
      }
      Synapse::ConfigGenerator::Envoy.new(conf)
      expect{Synapse::ConfigGenerator::Envoy.new(conf)}.not_to raise_error
    end
  end

  describe '#name' do
    it 'returns envoy' do
      expect(subject.name).to eq('envoy')
    end
  end

  describe 'basic operations' do
    it 'generates listener stanza' do
      mockConfig = []
      expect(subject.
               generate_listeners_stanza(mockwatcher_frontend_with_bind_address, mockConfig)).
        to eql({
        'address' => {
          'socket_address' => {
            'address' => '127.0.0.3',
            'port_value' => '9090',
          }
        },
        'filter_chains' => [{
          'filters' => [
            {
              'name' => 'envoy.tcp_proxy',
              'config' => {
                'stat_prefix' => 'ingress_tcp',
                'max_connect_attempts' => 3,
                'idle_timeout' => "60s",
                'cluster' => 'example_service5',
                'access_log' => [{
                  'name' => 'envoy.file_access_log',
                  'config' => {
                    'path' => '/var/log/envoy.log',
                  }
                }],
              }
            }
          ]
        }]
      })
    end

    it 'does not generate stanza if no port defined' do
      mockConfig = []
      expect(subject.
               generate_listeners_stanza(mockwatcher, mockConfig)).
        to eql({})
    end

    it 'generates a cluster stanza for each listener cluster' do
      mockConfig = []
      expect(subject.
               generate_clusters_stanza(mockwatcher, mockConfig)).
        to eql({"name"=>"example_service",
                "connect_timeout"=>"1s",
                "health_checks" => [{"timeout"=>"1s", "interval"=>"2s", "unhealthy_threshold"=>2, "healthy_threshold"=>3, "tcp_health_check"=>{"send"=>nil, "receive"=>nil}}],
                "type"=>"strict_dns", "lb_policy"=>"least_request",
                "hosts"=>[
                  {"socket_address"=>{"address"=>"somehost", "port_value"=>5555}},
                ]})
    end

    it 'generates a cluster stanza for each listener cluster' do
      mockConfig = []
      expect(subject.
               generate_clusters_stanza(mockwatcher_frontend_with_bind_address, mockConfig)).
        to eql({"name"=>"example_service5",
                "connect_timeout"=>"1s",
                "health_checks" => [{"timeout"=>"1s", "interval"=>"2s", "unhealthy_threshold"=>2, "healthy_threshold"=>3, "tcp_health_check"=>{"send"=>nil, "receive"=>nil}}],
                "type"=>"strict_dns",
                "lb_policy"=>"least_request",
                "hosts"=>[
                  {"socket_address"=>{"address"=>"somehost", "port_value"=>5555}},
                  {"socket_address"=>{"address"=>"somehost2", "port_value"=>5555}}]})
    end

    it 'generates a config for one service' do
      mockConfig = []
      expect(subject.
               generate_config([mockwatcher_frontend_with_bind_address])).
        to eql({"static_resources"=>{"listeners"=>[{"address"=>{"socket_address"=>{"address"=>"127.0.0.3", "port_value"=>"9090"}}, "filter_chains"=>[{"filters"=>[{"name"=>"envoy.tcp_proxy", "config"=>{"stat_prefix"=>"ingress_tcp", "max_connect_attempts" => 3, "idle_timeout" => "60s", "cluster"=>"example_service5", "access_log"=>[{"name"=>"envoy.file_access_log", "config"=>{"path"=>"/var/log/envoy.log"}}]}}]}]}], "clusters"=>[{"name"=>"example_service5", "connect_timeout"=>"1s", "type"=>"strict_dns", "lb_policy"=>"least_request", "hosts"=>[{"socket_address"=>{"address"=>"somehost", "port_value"=>5555}}, {"socket_address"=>{"address"=>"somehost2", "port_value"=>5555}}],"health_checks"=>[{"timeout"=>"1s", "interval"=>"2s", "unhealthy_threshold"=>2, "healthy_threshold"=>3, "tcp_health_check"=>{"send"=>nil, "receive"=>nil}}]}]}, "admin"=>{"access_log_path"=>"/dev/null", "address"=>{"socket_address"=>{"address"=>"127.0.0.1", "port_value"=>"8001"}}}})
    end
  end
end


