// Compatibility shims for building against a newer IDA SDK than the IDA
// installation we link and run against.
//
// The 9.40 SDK headers call lock_func_range_ea() from the destructors of
// func_tail_iterator_t / func_item_iterator_t (funcs.hpp), but IDA 9.3's
// libida.so only exports the older, pointer-based lock_func_range(). Any
// translation unit that touches those iterators therefore fails to link.
//
// Provide the ea-based entry point in terms of the older one. When the runtime
// does export the real symbol (9.4+) we forward to it, so this stays inert.

#ifndef _WIN32

#ifndef _GNU_SOURCE
#define _GNU_SOURCE // RTLD_NEXT
#endif
#include <dlfcn.h>

#include <pro.h>
#include <funcs.hpp>

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"

idaman void ida_export lock_func_range_ea(ea_t ea, bool lock)
{
  using lock_ea_fn = void (*)(ea_t, bool);
  static lock_ea_fn real = (lock_ea_fn)dlsym(RTLD_NEXT, "lock_func_range_ea");
  if ( real != nullptr )
  {
    real(ea, lock);
    return;
  }
  func_t *pfn = get_fchunk(ea);
  if ( pfn != nullptr )
    lock_func_range(pfn, lock);
}

#pragma GCC diagnostic pop
#pragma clang diagnostic pop

#endif // !_WIN32
