# SEAL-JS
SEAL (Secure Evidence Attribution Label) permits signing media for attribution.

This is an implementation of SEAL in JavaScript. The specifications are at: https://github.com/hackerfactor/SEAL

This code:
1. Validating signatures. This only requires DNS access. This code does *not* generate SEAL signatures; it only validates.
2. Runs completely in the web browser. There are no uploads to any web servers. There are also no trackers or embedded web bugs.
3. Optional: You can supply a "?source=*url*" to the URL. This will perform a web GET to retrieve the contents for evaluation.

This code currently supports static-files only. It does not support sidecars or streaming data. (The SEAL protocol supports streaming data, but this implementation does not (yet).)

## Usage
Load the (seal-validator.html)[seal-validator.html] file into the browser. This will load the seal-validator.js library; there are no other dependencies. Then, drag and drop whatever file(s) you want to evaluate. See (SEAL-C)[https://github.com/hackerfactor/SEAL-C] for the testsuite.

Alternately, developers can use the seal-validator.js library without seal-validate.html.

The file seal-tests.html contains the regression test suite. Opening it in a web browser immediately runs the tests.

## Supported Formats
SEAL supports a wide range of file formats. This JavaScript code supports:

|Image Format|Read Support|
|------|-------------|
|JPEG  |Yes|
|PNG   |Yes|
|GIF   |Yes|
|WEBP  |Yes|
|HEIC  |Yes|
|AVIF  |Yes|
|PNM/PPM/PGM|Yes|
|SVG   |Yes|
|TIFFⁱ  |Yes|
|JPEG XLⁱⁱ|Yes|
|DICOM |Yes|
|BMP   |No (no metadata support)|
|FAX   |No. Seriously, just no.|

ⁱ TIFF includes many camera-raw formats, including Adobe Digital Negative (DNG), Canon CRW and CR2, Hasselblad 3FR, Kodan KDC, Leica RAW, Nikon NEF, Panasonic Raw, Sony ARW, and many more.

ⁱⁱ JPEG XL uses ISO-BMFF for storing metadata and can be signed using SEAL. The raw JPEG XL stream does not support metadata and cannot be signed by SEAL.

|Audio Format|Read Support|
|------|-------------|
|AAC   |Yes|
|AVIF  |Yes|
|M4A   |Yes|
|MKA   |Yes|
|MP3   |Yes|
|MP3+ID3|Yes|
|MPEG  |Yes|
|WAV   |Yes|

|Video Format|Read Support|
|------|-------------|
|MP4   |Yes|
|3GP   |Yes|
|AVI   |Yes|
|AVIF  |Yes|
|HEIF  |Yes|
|HEVC  |Yes|
|DIVX  |Yes|
|MKV   |Yes|
|MOV/Quicktime |Yes|
|MPEG  |Yes|
|WEBM  |Yes|

|Document Format|Read Support|
|---------------|------------|
|PDF            |Yes         |
|XML            |Yes         |
|HTML           |Yes         |
|Plain Text     |Yes         |
|OpenDocument (docx, pptx, etc.)|Yes via ZIP|
|Electronic Publication (epub)|Yes via ZIP|

|Package Format|Read Support|
|--------------|------------|
|Java Archive (JAR)|Yes via ZIP|
|Android Application Package (APK)|Yes via ZIP|
|iOS Application Archive (iPA)|Yes via ZIP|
|Mozilla Extension (XPI)|Yes via ZIP|

|Container Format|Read Support|
|----------------|------------|
|EXIF            |Yes|
|XMP             |Yes|
|RIFF            |Yes|
|ISO-BMFF        |Yes|
|Matroska        |Yes|
|ZIP             |Yes|
|ZIP64           |Yes|

This is *not* every file format that `sealtool` supports! Many formats are based on other formats. (CR2 is based on TIFF, DIVX is based on RIFF, etc.). Similar formats are likely already supported. `sealtool` will only parse files when it recognizing the file format.

Have a format you need that isn't supported? Let us know!
