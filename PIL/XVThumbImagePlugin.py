#
# The Python Imaging Library.
# $Id$
#
# XV Thumbnail file handler by Charles E. "Gene" Cash
# (gcash@magicnet.net)
#
# see xvcolor.c and xvbrowse.c in the sources to John Bradley's XV,
# available from ftp://ftp.cis.upenn.edu/pub/xv/
#
# history:
# 98-08-15 cec  created (b/w only)
# 98-12-09 cec  added color palette
# 98-12-28 fl   added to PIL (with only a few very minor modifications)
#
# To do:
# FIXME: make save work (this requires quantization support)
#
from __future__ import annotations

from . import Image, ImageFile, ImagePalette
from ._binary import o8

_MAGIC = b"P7 332"

# standard color palette for thumbnails (RGB332)
PALETTE = b""

