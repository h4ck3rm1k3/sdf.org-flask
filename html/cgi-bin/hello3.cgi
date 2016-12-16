#!/usr/pkg/bin/perl
print "Content-Type: text/html\n\r\n\r";
print "<html><body><h2>Hello World!ENV</h2><pre>";
open (F,"<","/tmp/mike.txt");
while(<F>)    {
    print "<p>$_</p>";
}
close F;


print "</pre></body></html>";
