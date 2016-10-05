package NESSUS;
use Data::Dump qw(dump);
use Carp;
use LWP::UserAgent;
use JSON;
use List::Util qw(first);
use lib $ENV{'COMMON_HOME'}."/lib";
use EnhancedInfo;
use log_wrapper;
use warnings;
use strict;


sub new {
    my ($class, %params) = @_;
    my $url   = $params{url} || 'https://localhost:8834';
    my $agent = LWP::UserAgent->new();
    my $self = {
        url   => $url,
        agent => $agent,
    };
    bless $self, $class;

    return $self;
}



#=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=--=-=--=-=-
# Name     : create_session
# Desc     : Creates a new session token for the given user. Certificate based
#            logins require no parameters.  
# Args     :
#              1. (HASH)  : user's acount
# Example  :    my %account = (
#                   username => $Build::NESSUS_ID,
#                   password => $Build::NESSUS_PSW,
#               );
#              
# Returns  :
#              token - PASS | undef - FAIL
#=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=--=-=--=-=-
sub create_session {
    my ($self, %params) = @_;
    my $result = $self->_post("/session", %params);
    $self->{agent}->default_header(
        'X-Cookie' => "token=$result->{token}" );
    
    return $result->{token};
}


#=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=--=-=--=-=-
# Name     : destroy_session
# Desc     : Logs the current user out and destroys the session
# Args     :
#              1. ()  : 
#              
# Returns  :
#              0 - PASS | 1 - FAIL
#=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=--=-=--=-=-
sub destroy_session {
    my ($self, %params) = @_;

    my $response = $self->{agent}->delete($self->{url} . '/session');
    if ($response->is_success()) {
        return 0;
    } else {
        pError $response->message();
    }
    
    return 1;
}


sub create_scan {
    my ($self, %params) = @_;
    croak "missing uuid parameter" unless $params{uuid};
    croak "missing settings parameter" unless $params{settings};

    my $result = $self->_post("/scans", %params);
    pDebug dump %params;
    
    return $result->{scan};
}


sub get_policy_id {
    my ($self, %params) = @_;

    croak "missing name parameter" unless $params{name};

    my $policy = first { $_->{name} eq $params{name} } $self->list_policies();
    return unless $policy;

    return $policy->{id};
}


sub delete_policy {
    my ($self, %params) = @_;

    croak "missing Policy id parameter" unless $params{id};

    my $policy_id = delete $params{id};
    my $result = $self->_delete("/policies/$policy_id");

    return $result;
}


sub get_1st_template_id {
    my ($self, %params) = @_;

    croak "missing type parameter" unless $params{type};
    croak "invalid type parameter" unless $params{type} eq 'scan' or
                                          $params{type} eq 'policy';

    my $type = delete $params{type};
    my $result = $self->_get("/editor/$type/templates");
    my $template = $result->{templates}[0];
    print "Get 1st template: $template->{uuid} \n";

    return $template->{uuid};
}



sub get_template_id {
    my ($self, %params) = @_;

    croak "missing name parameter" unless $params{name};

    my $template =
        first { $_->{name} eq $params{name} }
        $self->list_templates(type => $params{type});
    return unless $template;

    return $template->{uuid};
}


sub list_templates {
    my ($self, %params) = @_;

    croak "missing type parameter" unless $params{type};
    croak "invalid type parameter" unless $params{type} eq 'scan' or
                                          $params{type} eq 'policy';

    my $type = delete $params{type};

    my $result = $self->_get("/editor/$type/templates");
    return $result->{templates} ? @{$result->{templates}} : ();
}


sub get_scan_status {
    my ($self, %params) = @_;

    croak "missing scan_id parameter" unless $params{scan_id};

    my $details = $self->get_scan_details(scan_id => $params{scan_id});
    
    return $details->{info}->{status};
}


sub get_scan_details {
    my ($self, %params) = @_;

    croak "missing scan_id parameter" unless $params{scan_id};

    my $scan_id = delete $params{scan_id};

    my $result = $self->_get("/scans/$scan_id", %params);
    
    return $result;
}


sub launch_scan {
    my ($self, %params) = @_;

    croak "missing scan_id parameter" unless $params{scan_id};
    my $scan_id = delete $params{scan_id};

    my $result = $self->_post("/scans/$scan_id/launch", %params);
    pInfo "launch a scan whose id is $scan_id.";
    
    return $result->{scan_uuid};
}


#=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=--=-=--=-=-
# Name     : export_scan
# Desc     : Export the given scan.
# Args     :
#              1. (HASH)  : See below example
# Example  :    my %param = (
#                   scan_id     => 101,
#                   history_id  => undef,   
#                   format      => 'pdf',
#                   password    => undef,
#                   chapters    => "vuln_hosts_summary" 
#                                  . ";vuln_by_host"
#                                  . ";compliance_exec"
#                                  . ";remediations"
#                                  . "vuln_by_plugin"
#                                  . ";compliance",
#               );
# Returns  :
#              file id - PASS | undef - FAIL
#=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=--=-=--=-=-
sub export_scan {
    my ($self, %params) = @_;

    croak "missing scan_id parameter" unless $params{scan_id};
    croak "missing format parameter" unless $params{format};
    croak "invalid format parameter" unless $params{format} eq 'nessus' or
                                            $params{format} eq 'html'   or
                                            $params{format} eq 'pdf'    or
                                            $params{format} eq 'csv'    or
                                            $params{format} eq 'db';
    my $scan_id = delete $params{scan_id};
    my $result = $self->_post("/scans/$scan_id/export", %params);

    return $result->{file};
}


sub get_scan_export_status {
    my ($self, %params) = @_;

    croak "missing scan_id parameter" unless $params{scan_id};
    croak "missing file_id parameter" unless $params{file_id};

    my $scan_id = delete $params{scan_id};
    my $file_id = delete $params{file_id};
    my $result = $self->_get("/scans/$scan_id/export/$file_id/status");
    
    return $result->{status};
}


#=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=--=-=--=-=-
# Name     : download_scan
# Desc     : Download an exported scan.
# Args     :
#              1. (HASH)  : See below example
# Example  :    my %param = (
#                   scan_id => 101,
#                   file_id => 326247438,
#                   filename => "$scan_name.pdf"
#               );
#              
# Returns  :
#              user-specified filename - PASS | 1 - FAIL
#=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=--=-=--=-=-
sub download_scan {
    my ($self, %params) = @_;

    croak "missing scan_id parameter" unless $params{scan_id};
    croak "missing file_id parameter" unless $params{file_id};

    my $scan_id = delete $params{scan_id};
    my $file_id = delete $params{file_id};

    my $response = $self->{agent}->get(
        $self->{url} . "/scans/$scan_id/export/$file_id/download",
        $params{filename} ? (':content_file' => $params{filename}) : ()
    );
    if ($response->is_success()) {
        return $params{filename} ? 1 : $response->content();
    } else {
        croak "communication error: " . $response->message()
    }
    
    return 1;
}


sub _get {
    my ($self, $path, %params) = @_;
    my $url = URI->new($self->{url} . $path);
    $url->query_form(%params);
    my $response = $self->{agent}->get($url);
    my $result = eval { from_json($response->content()) };

    if ($response->is_success()) {
        return $result;
        
    } else {
        if ($result) {
            croak "server error: " . $result->{error};
        } else {
            croak "communication error: " . $response->message()
        }
    }
    
    return 1;
}


sub _post {
    my ($self, $path, %params) = @_;
    my $content = to_json(\%params);
    my $url = $self->{url} . $path;
    my $response = $self->{agent}->post( $url,
        'Content-Type' => 'application/json',
        'Content'      => $content
    );

    my $result = eval { from_json($response->content()) };

    if ($response->is_success()) {
        return $result;
        
    } else {
        if ($result) {
            croak "server error: " . $result->{error};
        } else {
            croak "communication error: " . $response->message()
        }
    }

    return 1;
}

1;
__END__

See L<https://your.nessus.server:8834/nessus6-api.html#/