package ACUNETIXCLI;
use parent qw(Class::STAF);
use lib $ENV{'COMMON_HOME'}."/lib";
use log_wrapper;
use warnings;
use strict;


#=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=--=-=--=-=-
# Name     : scan
# Desc     : scan a single website
# Args     :
#              1. (SCALAR)  : host
#              2. (SCALAR)  : working path of the program
#              3. (HASH_ref): scan parameters
# Example  :    
#                my $target = $WIN7_32_HOST_IP; 
#                my $work_path = $WVS95_PATH; 
#                my $params_ref = {
#                   'uri'       => 'https://10.210.20.19',
#                   'profile'   => 'Default',
#                   'settings'  => 'Default',
#                   'loginseq'  => 'login_dut',
#                   'folder'    => 'C:\Report\Acunetix',
#                   'format'    => 'PDF',
#               };
# Returns  :
#              Summary of this scan - PASS | Error info. - FAIL
#=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=--=-=--=-=-
sub scan($$\%){
    if ($#_ < 3){
        die 'Usage: $obj->scan(TARGET, WORK_PATH, SCAN_PARAMETERS)';
    }
    my ( $self, $target, $work_path, $mParams) = @_;
    my $service = 'PROCESS';
    my $shell   = ' START SHELL COMMAND ';
    my $workdir = " WORKDIR $work_path ";
    my $wait    = ' WAIT 30m ';      ## timeout in 30 min
    my $program = " wvs_console.exe ";
    my $returnstdout = ' RETURNSTDOUT ';
    my $returnstderr = ' STDERRTOSTDOUT ';
    ## By default evaluation
    my $params_ref = {
        'uri'       => 'https://10.210.20.19',
        'profile'   => 'Default',
        'settings'  => 'Default',
        'loginseq'  => 'login_dut',
        'folder'    => 'C:\Report\Acunetix',
        'format'    => 'PDF',
    };
    foreach my $k (keys %$mParams){
        $params_ref->{$k} = $mParams->{$k};
    }
    my $wvs_params = " /Scan $params_ref->{uri}"
                    . " /Profile $params_ref->{profile}"
                    . " /Settings $params_ref->{settings}"
                    . " /LoginSeq $params_ref->{loginseq}"
                    . " /SaveFolder $params_ref->{folder}"
                    . " /GenerateReport"
                    . " /ReportFormat $params_ref->{format}"
                    . " /Save";
    my $param   = " PARMS $wvs_params ";
    my $mReqCmd = $shell 
                . $program
                . $workdir
                . $param
                . $returnstdout
                . $returnstderr
                . $wait
                ;
    return $self->_submit($target, $service, $mReqCmd);
}


#=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=--=-=--=-=-
# Name     : staf_ping
# Desc     : ping by using staf
# Args     :
#              1. (SCALAR)  : host
# Example  :    my $target = 'local' ## or host's ip address
#              
# Returns  :
#              PONG - PASS | undef - FAIL
#=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=--=-=--=-=-
sub staf_ping($$){
    if ($#_ < 1){
        die 'Usage: $obj->staf_ping(TARGET)';
    }
    my ( $self, $target) = @_;
    
    return $self->_submit($target, "PING", "PING");
}


#=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=--=-=--=-=-
# Name     : destroy
# Desc     : Unregister staf handle
# Returns  :
#              undef - PASS | Error info. - FAIL
#=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=--=-=--=-=-
sub destroy{
    my $self = shift;
    return $self->SUPER::DESTROY;
}


#=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=--=-=--=-=-
# Name     : copy
# Desc     : copy file to remote machine
# Args     :
#              1. (SCALAR): host
#              2. (SCALAR): nickname of remote machine
#              3. (SCALAR): file
#              4. (SCALAR): destination file
# Example  :    
#                my $host = $ATTACKER_HOST_IP; 
#                my $to_machine = $VTB126_MACHINE_NAME; 
#                my $file = 'C:\Report\Acunetix\report.pdf';
#                my $toFile = "$REPORT_PATH/$report_name";
# Returns  :
#              Summary of this scan - PASS | Error info. - FAIL
#=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=--=-=--=-=-
sub copy(\$$){
    if ($#_ < 4){
        die 'Usage: $obj->copy(HOST, TOMACHINE, FILE, TOFILE)';
    }
    my ( $self, $target, $to, $mFile, $mToFile ) = @_; 
    my $service = 'FS';
    my $copy    = ' COPY FILE ';
    my $tomachine = " TOMACHINE $to ";
    my $tofile = " TOFILE $mToFile";
    ## Conjunctate to a request
    my $request = $copy
                . $mFile
                . $tofile
                . $tomachine
                ;
    return $self->_submit($target, $service, $request);
}


sub _submit{
    if ($#_ < 3){
        die 'Usage: $obj->_staf_submit(HOST, SERVICE, REQUEST)';
    }
    my $self = shift;
    ## host, service and request objects
    my ($mHost, $mService, $mRequest) = @_;
    pInfo "staf $mHost $mService $mRequest";
    my $result = $self->SUPER::submit($mHost, $mService, $mRequest)
        or pError "Submit failed ($!): $self->SUPER::LastError";

    return $result;
}
1;
__END__
=head1 NAME

ACUNETIXCLI - Call Acunetix console using Class::STAF API

=head1 SYNOPSIS

    use ACUNETIXCLI;
    my $acunetix_obj = ACUNETIXCLI->new('wvs_console');
    my $retvl = $acunetix_obj->staf_ping('local');

    my %scan_params = (
        'uri'       => 'https://10.210.20.19',
        'profile'   => 'Default',
        'settings'  => 'Default',
        'loginseq'  => 'login_dut',
        'folder'    => 'C:\Report\Acunetix',
        'format'    => 'PDF',
    );
    my $workdir =  'C:\"Program Files"\Acunetix\"Web Vulnerability Scanner 9.5"';
    $retvl = $acunetix_obj->scan($machine, $workdir, \%scan_params);
    
    my $file = 'C:\Report\Acunetix\report.pdf';
    my $toFile = '/tmp/dest_report.pdf';
    my $retvl = $acunetix_obj->copy('local', 'local', $file, $toFile);

=head1 DESCRIPTION

This module is an API for Acunetix console calling by using STAF - More Perlish.

For more info about STAF: http://staf.sourceforge.net/

Instead of checking for every request that the return code is zero, and only then
proceed, this API return the answer immidiatly. Only if the return code is not zero,
the submit will return undef. Then the return code is saved in $!, and the error message
can be retrived using $handle->LastError command.

Also export by default the Marshall and UnMarshall functions from L<Class::STAF::Marshalled>,
and will export by request the get_staf_fields and get_staf_class_name.

=head1 The Class::STAF object

The functions are similar to the original STAF API.
Creating:

    my $handle =ACUNETIXCLI->new("My Program")
        or die "Error: can not create handle. RC=$!";

The new function only return a return code.

Member functions:
    
    submit
    submit2

Will automatically un-register the STAF handle on destroy.

=head1 Creating Host and Service objects

    my $host = $handle->host("local");

will create an object to communicate with the local computer. usefull when you make
repeating request to the same computer. And using it is similar to how we use the
handle object, minus the host parameter:

    my $result = $host->submit("PING", "PING") or die "Oops\n";

Also, we can create a service object:

    my $service = $host->service("PING");

And use it:

    $service->submit("PING") or die "Ping is not working on that host?!";

=head1 Thread Safety

This module is thread safe by itself, but it is based on PLSTAF. It is still not clear
wether the PLSTAF module is thread safe or not.

Also, this warpper will automatically unregister the STAF Handle only after
it is released from all the threads that use it.

As result of this thread safety, this module support Perl 5.6.1 and up.

=head1 BUGS

Non known.

This is a first release - your feedback will be appreciated.

=head1 SEE ALSO

STAF homepage: http://staf.sourceforge.net/

The L<STAFService> CPAN module.

Object Marshalling API: L<Class::STAF::Marshalled>

=head1 AUTHOR

Bruce Jiang<lt>bluce_jyy@hotmail.com<gt>

=head1 COPYRIGHT AND LICENSE

Copyright 2016 by Bruce Jiang.

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself. 

=cut