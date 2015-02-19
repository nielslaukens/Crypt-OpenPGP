use strict;
use Test::More;

use Crypt::OpenPGP::Plaintext;
use Crypt::OpenPGP::UserID;
use Crypt::OpenPGP::Buffer;
use Crypt::OpenPGP::Constants qw( PGP_PKT_USER_ID PGP_PKT_PLAINTEXT );

use_ok 'Crypt::OpenPGP::PacketFactory';

## 184 bytes
my $text = <<TEXT;
we are the synchronizers
send messages through time code
midi clock rings in my mind
machines gave me some freedom
synthesizers gave me some wings
they drop me through 12 bit samplers
TEXT

my $id = 'Foo Bar <foo@bar.com>';

my @pkt;
push @pkt, # Signature with notation
"\x89\x00\xbb\x04\x10\x01\x08\x00\x25\x05\x02\x54\xe5" .
"\xd1\x05\x1e\x14\x80\x00\x00\x00\x00\x10\x00\x05\x6e" .
"\x61\x6d\x65\x40\x65\x78\x61\x6d\x70\x6c\x65\x2e\x63" .
"\x6f\x6d\x76\x61\x6c\x75\x65\x00\x0a\x09\x10\xb7\x89" .
"\x66\xa1\x51\x37\xf1\x89\x14\x5d\x04\x00\x94\xd2\xf9" .
"\xf3\x4d\x89\xf4\x49\xf8\xab\x0d\xd2\x23\x49\x10\x5c" .
"\x8c\xae\xe6\x75\xea\x94\xbd\xd6\x21\xe1\xa9\xf5\xc4" .
"\xd7\x51\x65\xad\x78\x82\x15\x0b\x0b\x2b\x4f\x96\xe7" .
"\x07\x60\xcc\xc4\xfc\x1b\x54\x7e\xd3\xa6\x79\x42\x66" .
"\x3a\x8e\x50\xb4\xf3\x82\x5c\x9f\x41\x7d\x43\x14\xf3" .
"\x02\x8e\x81\x60\x2a\xd9\xf9\x1e\x16\x91\xdc\xf0\xee" .
"\xf7\x63\x68\xb6\x88\x8e\x08\xb1\x79\x36\x87\x86\xce" .
"\x3f\xb5\x1f\x04\x51\x79\x60\x32\x53\xdd\x68\x58\x71" .
"\x8f\x78\x78\xb0\x9e\xae\x86\x0e\x00\x80\xed\xaa\x41" .
"\x06\x94\x4c\x76\x8c\x8b\x7e\xa9";

plan tests => 19 + 2*@pkt;

# Saving packets
my $pt = Crypt::OpenPGP::Plaintext->new( Data => $text );
isa_ok $pt, 'Crypt::OpenPGP::Plaintext';
my $ptdata = $pt->save;
my $ser = Crypt::OpenPGP::PacketFactory->save( $pt );
ok $ser, 'save serializes our packet';
# 1 ctb tag, 1 length byte
is length( $ser ) - length( $ptdata ), 2, '2 bytes for header';

# Test pkt_hdrlen override of hdrlen calculation
# Force Plaintext packets to use 2-byte length headers
*Crypt::OpenPGP::Plaintext::pkt_hdrlen =
*Crypt::OpenPGP::Plaintext::pkt_hdrlen = sub { 2 };

$ser = Crypt::OpenPGP::PacketFactory->save( $pt );
ok $ser, 'save serializes our packet';
# 1 ctb tag, 2 length byte
is length( $ser ) - length( $ptdata ), 3, 'now 3 bytes per header';

# Reading packets from serialized buffer
my $buf = Crypt::OpenPGP::Buffer->new;
$buf->append( $ser );
my $pt2 = Crypt::OpenPGP::PacketFactory->parse( $buf );
isa_ok $pt2, 'Crypt::OpenPGP::Plaintext';
is_deeply $pt, $pt2, 'parsing serialized packet yields original';

# Saving multiple packets
my $userid = Crypt::OpenPGP::UserID->new( Identity => $id );
isa_ok $userid, 'Crypt::OpenPGP::UserID';
$ser = Crypt::OpenPGP::PacketFactory->save( $pt, $userid, $pt );
ok $ser, 'save serializes our packet';

$buf = Crypt::OpenPGP::Buffer->new;
$buf->append( $ser );

my( @pkts, $pkt );
push @pkts, $pkt while $pkt = Crypt::OpenPGP::PacketFactory->parse( $buf );
is_deeply \@pkts, [ $pt, $userid, $pt ],
    'parsing multiple packets gives us back all 3 originals';

# Test finding specific packets
@pkts = ();
$buf->reset_offset;
push @pkts, $pkt
    while $pkt = Crypt::OpenPGP::PacketFactory->parse(
        $buf,
        [ PGP_PKT_USER_ID ]
    );
is_deeply \@pkts, [ $userid ], 'only 1 userid packet found';

@pkts = ();
$buf->reset_offset;
push @pkts, $pkt
    while $pkt = Crypt::OpenPGP::PacketFactory->parse(
        $buf,
        [ PGP_PKT_PLAINTEXT ]
    );
is_deeply \@pkts, [ $pt, $pt ], '2 plaintext packets found';

# Test finding, but not parsing, specific packets

@pkts = ();
$buf->reset_offset;
push @pkts, $pkt
    while $pkt = Crypt::OpenPGP::PacketFactory->parse(
        $buf,
        [ PGP_PKT_PLAINTEXT, PGP_PKT_USER_ID ],
        [ PGP_PKT_USER_ID ],
    );
is @pkts, 3, 'found all 3 packets';
isa_ok $pkts[0], 'HASH';
ok $pkts[0]->{__unparsed}, 'plaintext packets are unparsed';
is_deeply $pkts[1], $userid, 'userid packets are parsed';
isa_ok $pkts[2], 'HASH';
ok $pkts[2]->{__unparsed}, 'plaintext packets are unparsed';

use Data::Dumper;
my $i = 0;
do {
	$buf->empty();
	$buf->put_bytes($pkt[$i]);
	my $parsed = Crypt::OpenPGP::PacketFactory->parse($buf);
	isnt $parsed, undef, "Parsed packet $i";
	my $saved = Crypt::OpenPGP::PacketFactory->save($parsed);
	is $saved, $pkt[$i], "parse-save roundtrip identical for packet $i";
} while( ++$i < @pkt );
