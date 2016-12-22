#!/usr/pkg/bin/perl
print "Content-Type: text/html\n\r\n\r";
print "<html><body><h2>Hello World from perl!ENV</h2></body></html>";
open (F,">","/tmp/mike.txt");
my $now_string = localtime;
print "$now_string";
print F "$now_string\n";
for my $k (keys %ENV){
    my $v= $ENV{$k};
    print "<p>$k -> $v</p>";
    print F "<p>$k -> $v</p>\n";
}
close F;

#system('./hello.cgi');
print "h2>calling flask</h2>\n";
system('./helloflask.cgi');

<<<<<<< HEAD
=======
print "h2>logs</h2>\n";
print "<pre>";
open (F,"<","/tmp/mike.txt");
while(<F>)    {
    print "<p>$_</p>";
}
close F;

print "</pre>";


>>>>>>> abe0a46... update
