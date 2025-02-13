for r in range(8):
    for g in range(8):
        for b in range(4):
            PALETTE = PALETTE + (
                o8((r * 255) // 7) + o8((g * 255) // 7) + o8((b * 255) // 3)
            )


def _accept(prefix):
    return prefix[:6] == _MAGIC


##
# Image plugin for XV thumbnail images.


class XVThumbImageFile(ImageFile.ImageFile):
    format = "XVThumb"
    format_description = "XV thumbnail image"

    def _open(self):
        # check magic
        if not _accept(self.fp.read(6)):
            msg = "not an XV thumbnail file"
            raise SyntaxError(msg)

        # Skip to beginning of next line
        self.fp.readline()

        # skip info comments
        while True:
            s = self.fp.readline()
            if not s:
                msg = "Unexpected EOF reading XV thumbnail file"
                raise SyntaxError(msg)
            if s[0] != 35:  # ie. when not a comment: '#'
                break

        # parse header line (already read)
        s = s.strip().split()

        self._mode = "P"
        self._size = int(s[0]), int(s[1])

        self.palette = ImagePalette.raw("RGB", PALETTE)

        self.tile = [("raw", (0, 0) + self.size, self.fp.tell(), (self.mode, 0, 1))]


# --------------------------------------------------------------------

Image.register_open(XVThumbImageFile.format, XVThumbImageFile, _accept)
