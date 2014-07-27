============
vmod_imgdata
============

----------------------
Varnish Imgdata Module
----------------------

:Author: Wojciech Wierchola <admin@webcarrot.pl>
:Date: 2014-07-26
:Version: 0.1
:Manual section: 3

SYNOPSIS
========

Basically based on Aivars Kalvans libvmod-rewrite.

Using CURL to download images and GNU coreutils base64
implementation.

DESCRIPTION
===========

Varnish vmod that replace images urls with

"data:image/{EXT};base64,{IMAGE_DATA}".

Imgdata is performed only once and the rewritten document is stored
in cache.

FUNCTIONS
=========

imgdata_re
----------

Prototype
        ::

                imgdata_re(STRING POSTFIX_REGEX)
Return value
  VOID
Description
  Replace all parts of document matching
    "https?://[^\"' ]+\\.(jpg|jpeg|png|gif){POSTFIX_REGEX}"
  with
    "data:image/{EXT};base64,{IMAGE_DATA}"

INSTALLATION
============

Usage::

 ./configure VARNISHSRC=DIR [VMODDIR=DIR]

`VARNISHSRC` is the directory of the Varnish source tree for which to
compile your vmod. Both the `VARNISHSRC` and `VARNISHSRC/include`
will be added to the include search paths for your module.

Optionally you can also set the vmod install directory by adding
`VMODDIR=DIR` (defaults to the pkg-config discovered directory from your
Varnish installation).

Make targets:

* make - builds the vmod
* make install - installs your vmod in `VMODDIR`

In your VCL you could then use this vmod along the following lines::
    
    import imgdata;
     
    sub vcl_deliver {  
        if (
            resp.http.Content-Type ~ "text/html" ||
            resp.http.Content-Type ~ "text/css"  ||
            resp.http.Content-Type ~ "application/json"
        ) {
            imgdata.imgdata_re("\?inline=true");
        }
    }

TODO
====

* Database/cache for base64 form of images
* Output compression
* Output content buffer updates optimization

COPYRIGHT
=========

Wojciech Wierchola 2014

See LICENCE (GPLv3) for details.
