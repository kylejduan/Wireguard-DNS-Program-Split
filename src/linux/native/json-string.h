// SPDX-License-Identifier: GPL-3.0-or-later
// Included by bpf-loader.cpp inside its private namespace.
/* JSON string for raw filesystem bytes: valid UTF-8 is kept, and each byte of
 * an invalid sequence becomes a lone surrogate escape, matching Python's
 * surrogateescape decoding of the same path. */
std::string json_string(const std::string &text) {
    std::string output="\"";
    for (size_t i=0;i<text.size();i++) {
        unsigned char ch=text[i];
        if (ch=='"' || ch=='\\') { output+='\\'; output+=ch; }
        else if (ch<32) { output+="\\u00"; output+="0123456789abcdef"[ch>>4]; output+="0123456789abcdef"[ch&15]; }
        else if (ch<128) output+=ch;
        else {
            size_t length=ch>=0xc2 && ch<=0xdf ? 2 : ch>=0xe0 && ch<=0xef ? 3 : ch>=0xf0 && ch<=0xf4 ? 4 : 0;
            bool valid=length && i+length<=text.size();
            for (size_t n=1;valid && n<length;n++) valid=(static_cast<unsigned char>(text[i+n])&0xc0)==0x80;
            if (valid) {
                unsigned char second=text[i+1];
                valid=!((ch==0xe0 && second<0xa0) || (ch==0xed && second>=0xa0) ||
                        (ch==0xf0 && second<0x90) || (ch==0xf4 && second>=0x90));
            }
            if (valid) { output.append(text,i,length); i+=length-1; }
            else { output+="\\udc"; output+="0123456789abcdef"[ch>>4]; output+="0123456789abcdef"[ch&15]; }
        }
    }
    return output+'"';
}
