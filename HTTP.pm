=head1 NAME

AnyEvent::HTTP - simple but non-blocking HTTP/HTTPS client

=head1 SYNOPSIS

   use AnyEvent::HTTP;

=head1 DESCRIPTION

This module is an L<AnyEvent> user, you need to make sure that you use and
run a supported event loop.

=head2 METHODS

=over 4

=cut

package AnyEvent::HTTP;

use strict;
no warnings;

use Carp;

use AnyEvent ();
use AnyEvent::Util ();
use AnyEvent::Socket ();
use AnyEvent::Handle ();

use base Exporter::;

our $VERSION = '1.0';

our @EXPORT = qw(http_get http_request);

our $MAX_REDIRECTS      = 10;
our $USERAGENT          = "Mozilla/5.0 (compatible; AnyEvent::HTTP/$VERSION; +http://software.schmorp.de/pkg/AnyEvent)";
our $MAX_PERSISTENT     =  8;
our $PERSISTENT_TIMEOUT = 15;
our $TIMEOUT            = 60;

# changing these is evil
our $MAX_PERSISTENT_PER_HOST = 2;
our $MAX_PER_HOST       = 4; # not respected yet :(

my %KA_COUNT; # number of open keep-alive connections per host

=item http_get $url, key => value..., $cb->($data, $headers)

Executes an HTTP-GET request. See the http_request function for details on
additional parameters.

=item http_request $method => $url, key => value..., $cb->($data, $headers)

Executes a HTTP request of type C<$method> (e.g. C<GET>, C<POST>). The URL
must be an absolute http or https URL.

Additional parameters are key-value pairs, and are fully optional. They
include:

=over 4

=item recurse => $boolean (default: true)

Whether to recurse requests or not, e.g. on redirects, authentication
retries and so on.

=item headers => hashref

The request headers to use.

=item timeout => $seconds

The time-out to use for various stages - each connect attempt will reset
the timeout, as will read or write activity.

=back

=back

=cut

sub http_request($$$;@) {
   my $cb = pop;
   my ($method, $url, %arg) = @_;

   my %hdr;

   if (my $hdr = delete $arg{headers}) {
      while (my ($k, $v) = each %$hdr) {
         $hdr{lc $k} = $v;
      }
   }

   my $timeout = $arg{timeout} || $TIMEOUT;

   $hdr{"user-agent"} ||= $USERAGENT;

   my ($scheme, $authority, $path, $query, $fragment) =
      $url =~ m|(?:([^:/?#]+):)?(?://([^/?#]*))?([^?#]*)(?:\?([^#]*))?(?:#(.*))?|;

   $scheme = lc $scheme;
   my $port = $scheme eq "http"  ? 80
            : $scheme eq "https" ? 443
            : croak "$url: only http and https URLs supported";

   $authority =~ /^(?: .*\@ )? ([^\@:]+) (?: : (\d+) )?$/x
      or croak "$authority: unparsable URL";

   my $host = $1;
   $port = $2 if defined $2;

   $host =~ s/^\[(.*)\]$/$1/;
   $path .= "?$query" if length $query;

   $hdr{host} = $host = lc $host;

   my %state;

   my $body = "";
   $state{body} = $body;

   $hdr{"content-length"} = length $body;

   $state{connect_guard} = AnyEvent::Socket::tcp_connect $host, $port, sub {
      $state{fh} = shift
         or return $cb->(undef, { Status => 599, Reason => "$!" });

      delete $state{connect_guard}; # reduce memory usage, save a tree

      # get handle
      $state{handle} = new AnyEvent::Handle
         fh => $state{fh},
         ($scheme eq "https" ? (tls => "connect") : ());

      # limit the number of persistent connections
      if ($KA_COUNT{$_[1]} < $MAX_PERSISTENT_PER_HOST) {
         ++$KA_COUNT{$_[1]};
         $state{handle}{ka_count_guard} = AnyEvent::Util::guard { --$KA_COUNT{$_[1]} };
         $hdr{connection} = "keep-alive";
      } else {
         delete $hdr{connection};
      }

      # (re-)configure handle
      $state{handle}->timeout ($timeout);
      $state{handle}->on_error (sub {
         %state = ();
         $cb->(undef, { Status => 599, Reason => "$!" });
      });
      $state{handle}->on_eof (sub {
         %state = ();
         $cb->(undef, { Status => 599, Reason => "unexpected end-of-file" });
      });

      # send request
      $state{handle}->push_write (
         "\U$method\E $path HTTP/1.0\015\012"
         . (join "", map "$_: $hdr{$_}\015\012", keys %hdr)
         . "\015\012"
         . (delete $state{body})
      );

      %hdr = (); # reduce memory usage, save a kitten

      # status line
      $state{handle}->push_read (line => qr/\015?\012/, sub {
         $_[1] =~ /^HTTP\/([0-9\.]+) \s+ ([0-9]{3}) \s+ ([^\015\012]+)/ix
            or return (%state = (), $cb->(undef, { Status => 599, Reason => "invalid server response ($_[1])" }));

         my %hdr = ( # response headers
            HTTPVersion => ",$1",
            Status      => ",$2",
            Reason      => ",$3",
         );

         # headers, could be optimized a bit
         $state{handle}->unshift_read (line => qr/\015?\012\015?\012/, sub {
            for ("$_[1]\012") {
               $hdr{lc $1} .= ",$2"
                  while /\G
                        ([^:\000-\040]+):
                        [\011\040]*
                        ((?: [^\015\012]+ | \015?\012[\011\040] )*)
                        \015?\012
                     /gxc;

               /\G$/
                 or return $cb->(undef, { Status => 599, Reason => "garbled response headers" });
            }

            substr $_, 0, 1, ""
               for values %hdr;

            if (exists $hdr{"content-length"}) {
               $_[0]->unshift_read (chunk => $hdr{"content-length"}, sub {
                  # could cache persistent connection now
                  if ($hdr{connection} =~ /\bkeep-alive\b/i) {
                  };

                  %state = ();
                  $cb->($_[1], \%hdr);
               });
            } else {
               # too bad, need to read until we get an error or EOF,
               # no way to detect winged data.
               $_[0]->on_error (sub {
                  %state = ();
                  $cb->($_[0]{rbuf}, \%hdr);
               });
               $_[0]->on_eof (undef);
               $_[0]->on_read (sub { });
            }
         });
      });
   }, sub {
      $timeout
   };

   defined wantarray && AnyEvent::Util::guard { %state = () }
}

sub http_get($$;@) {
   unshift @_, "GET";
   &http_request
}

=head2 GLOBAL VARIABLES

=over 4

=item $AnyEvent::HTTP::MAX_REDIRECTS

The default value for the C<max_redirects> request parameter
(default: C<10>).

=item $AnyEvent::HTTP::USERAGENT

The default value for the C<User-Agent> header (the default is
C<Mozilla/5.0 (compatible; AnyEvent::HTTP/$VERSION; +http://software.schmorp.de/pkg/AnyEvent)>).

=item $AnyEvent::HTTP::MAX_PERSISTENT

The maximum number of persistent connections to keep open (default: 8).

=item $AnyEvent::HTTP::PERSISTENT_TIMEOUT

The maximum time to cache a persistent connection, in seconds (default: 15).

=back

=cut

=head1 SEE ALSO

L<AnyEvent>.

=head1 AUTHOR

 Marc Lehmann <schmorp@schmorp.de>
 http://home.schmorp.de/

=cut

1

