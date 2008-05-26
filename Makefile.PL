use ExtUtils::MakeMaker;

my $mm = MM->new({
    dist         => {
       PREOP	=> 'pod2text LWP.pm | tee README >$(DISTVNAME)/README; chmod -R u=rwX,go=rX . ;',
       COMPRESS	=> 'gzip -9v',
       SUFFIX	=> '.gz',
	            },
    NAME         => "AnyEvent::LWP",
    VERSION_FROM => "LWP.pm",
    PREREQ_PM    => {
       AnyEvent  => 4.05,
       LWP       => 5,
    },
});

$mm->flush;

