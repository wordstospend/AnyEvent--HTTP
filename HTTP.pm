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

our $USERAGENT          = "Mozilla/5.0 (compatible; AnyEvent::HTTP/$VERSION; +http://software.schmorp.de/pkg/AnyEvent)";
our $MAX_RECURSE        =  10;
our $MAX_PERSISTENT     =   8;
our $PERSISTENT_TIMEOUT =   2;
our $TIMEOUT            = 300;

# changing these is evil
our $MAX_PERSISTENT_PER_HOST = 2;
our $MAX_PER_HOST       = 4; # not respected yet :(

our $PROXY;

my %KA_COUNT; # number of open keep-alive connections per host

=item http_get $url, key => value..., $cb->($data, $headers)

Executes an HTTP-GET request. See the http_request function for details on
additional parameters.

=item http_get $url, $body, key => value..., $cb->($data, $headers)

Executes an HTTP-POST request with a requets body of C<$bod>. See the
http_request function for details on additional parameters.

=item http_request $method => $url, key => value..., $cb->($data, $headers)

Executes a HTTP request of type C<$method> (e.g. C<GET>, C<POST>). The URL
must be an absolute http or https URL.

The callback will be called with the response data as first argument
(or C<undef> if it wasn't available due to errors), and a hash-ref with
response headers as second argument.

All the headers in that has are lowercased. In addition to the response
headers, the three "pseudo-headers" C<HTTPVersion>, C<Status> and
C<Reason> contain the three parts of the HTTP Status-Line of the same
name.

If an internal error occurs, such as not being able to resolve a hostname,
then C<$data> will be C<undef>, C<< $headers->{Status} >> will be C<599>
and the C<Reason> pseudo-header will contain an error message.

Additional parameters are key-value pairs, and are fully optional. They
include:

=over 4

=item recurse => $count (default: $MAX_RECURSE)

Whether to recurse requests or not, e.g. on redirects, authentication
retries and so on, and how often to do so.

=item headers => hashref

The request headers to use.

=item timeout => $seconds

The time-out to use for various stages - each connect attempt will reset
the timeout, as will read or write activity. Default timeout is 5 minutes.

=item proxy => [$host, $port[, $scheme]] or undef

Use the given http proxy for all requests. If not specified, then the
default proxy (as specified by C<$ENV{http_proxy}>) is used.

C<$scheme> must be either missing or C<http> for HTTP, or C<https> for
HTTPS.

=item body => $string

The request body, usually empty. Will be-sent as-is (future versions of
this module might offer more options).

=back

=back

=cut

sub http_request($$$;@) {
   my $cb = pop;
   my ($method, $url, %arg) = @_;

   my %hdr;

   $method = uc $method;

   if (my $hdr = delete $arg{headers}) {
      while (my ($k, $v) = each %$hdr) {
         $hdr{lc $k} = $v;
      }
   }

   my $proxy   = $arg{proxy}   || $PROXY;
   my $timeout = $arg{timeout} || $TIMEOUT;
   my $recurse = exists $arg{recurse} ? $arg{recurse} : $MAX_RECURSE;

   $hdr{"user-agent"} ||= $USERAGENT;

   my ($host, $port, $path, $scheme);

   if ($proxy) {
      ($host, $port, $scheme) = @$proxy;
      $path = $url;
   } else {
      ($scheme, my $authority, $path, my $query, my $fragment) =
         $url =~ m|(?:([^:/?#]+):)?(?://([^/?#]*))?([^?#]*)(?:\?([^#]*))?(?:#(.*))?|;

      $port = $scheme eq "http"  ?  80
            : $scheme eq "https" ? 443
            : croak "$url: only http and https URLs supported";

      $authority =~ /^(?: .*\@ )? ([^\@:]+) (?: : (\d+) )?$/x
         or croak "$authority: unparsable URL";

      $host = $1;
      $port = $2 if defined $2;

      $host =~ s/^\[(.*)\]$/$1/;
      $path .= "?$query" if length $query;

      $path = "/" unless $path;

      $hdr{host} = $host = lc $host;
   }

   $scheme = lc $scheme;

   my %state;

   $state{body} = delete $arg{body};

   $hdr{"content-length"} = length $state{body};

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
         delete $hdr{connection}; # keep-alive not yet supported
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
         "$method $path HTTP/1.0\015\012"
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
               # we support spaces in field names, as lotus domino
               # creates them.
               $hdr{lc $1} .= ",$2"
                  while /\G
                        ([^:\000-\037]+):
                        [\011\040]*
                        ((?: [^\015\012]+ | \015?\012[\011\040] )*)
                        \015?\012
                     /gxc;

               /\G$/
                 or return $cb->(undef, { Status => 599, Reason => "garbled response headers" });
            }

            substr $_, 0, 1, ""
               for values %hdr;

            if ($method eq "HEAD") {
               %state = ();
               $cb->(undef, \%hdr);
            } else {
               if (exists $hdr{"content-length"}) {
                  $_[0]->unshift_read (chunk => $hdr{"content-length"}, sub {
                     # could cache persistent connection now
                     if ($hdr{connection} =~ /\bkeep-alive\b/i) {
                        # but we don't, due to misdesigns, this is annoyingly complex
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

sub http_head($$;@) {
   unshift @_, "HEAD";
   &http_request
}

sub http_post($$$;@) {
   unshift @_, "POST", "body";
   &http_request
}

=head2 GLOBAL FUNCTIONS AND VARIABLES

=over 4

=item AnyEvent::HTTP::set_proxy "proxy-url"

Sets the default proxy server to use. The proxy-url must begin with a
string of the form C<http://host:port> (optionally C<https:...>).

=item $AnyEvent::HTTP::MAX_RECURSE

The default value for the C<recurse> request parameter (default: C<10>).

=item $AnyEvent::HTTP::USERAGENT

The default value for the C<User-Agent> header (the default is
C<Mozilla/5.0 (compatible; AnyEvent::HTTP/$VERSION; +http://software.schmorp.de/pkg/AnyEvent)>).

=item $AnyEvent::HTTP::MAX_PERSISTENT

The maximum number of persistent connections to keep open (default: 8).

Not implemented currently.

=item $AnyEvent::HTTP::PERSISTENT_TIMEOUT

The maximum time to cache a persistent connection, in seconds (default: 2).

Not implemented currently.

=back

=cut

sub set_proxy($) {
   $PROXY = [$2, $3 || 3128, $1] if $_[0] =~ m%^(https?):// ([^:/]+) (?: : (\d*) )?%ix;
}

# initialise proxy from environment
set_proxy $ENV{http_proxy};

=head1 SEE ALSO

L<AnyEvent>.

=head1 AUTHOR

 Marc Lehmann <schmorp@schmorp.de>
 http://home.schmorp.de/

=cut

1

