import ctypes as c, re,sys
from pathlib import Path
r=c.CDLL('librsvg-2.so.2'); cairo=c.CDLL('libcairo.so.2');g=c.CDLL('libgobject-2.0.so.0')
class Rect(c.Structure): _fields_=[('x',c.c_double),('y',c.c_double),('width',c.c_double),('height',c.c_double)]
r.rsvg_handle_new_from_file.argtypes=[c.c_char_p,c.c_void_p];r.rsvg_handle_new_from_file.restype=c.c_void_p
r.rsvg_handle_render_document.argtypes=[c.c_void_p,c.c_void_p,c.POINTER(Rect),c.c_void_p];r.rsvg_handle_render_document.restype=c.c_int
cairo.cairo_image_surface_create.argtypes=[c.c_int,c.c_int,c.c_int];cairo.cairo_image_surface_create.restype=c.c_void_p
cairo.cairo_create.argtypes=[c.c_void_p];cairo.cairo_create.restype=c.c_void_p
cairo.cairo_surface_write_to_png.argtypes=[c.c_void_p,c.c_char_p];cairo.cairo_surface_write_to_png.restype=c.c_int
cairo.cairo_destroy.argtypes=[c.c_void_p];cairo.cairo_surface_destroy.argtypes=[c.c_void_p];g.g_object_unref.argtypes=[c.c_void_p]
source,target=sys.argv[1:3]
v=list(map(float,re.search(r'viewBox="([^"]+)"',Path(source).read_text()).group(1).split()))
w,h=max(1,round(v[2]*2)),max(1,round(v[3]*2))
s=cairo.cairo_image_surface_create(0,w,h);ctx=cairo.cairo_create(s);handle=r.rsvg_handle_new_from_file(source.encode(),None)
assert handle and r.rsvg_handle_render_document(handle,ctx,c.byref(Rect(0,0,w,h)),None)
assert cairo.cairo_surface_write_to_png(s,target.encode())==0
cairo.cairo_destroy(ctx);cairo.cairo_surface_destroy(s);g.g_object_unref(handle)
print(f'{target}: {w}x{h}')
