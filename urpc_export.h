
#ifndef URPC_API_EXPORT_H
#define URPC_API_EXPORT_H

#ifdef URPC_STATIC_DEFINE
    #define URPC_API_EXPORT
    #define URPC_NO_EXPORT
#else
    #ifndef URPC_API_EXPORT
        #ifdef urpc_EXPORTS
            /* We are building this library */
            #define URPC_API_EXPORT
        #else
            /* We are using this library */
            #define URPC_API_EXPORT
        #endif
    #endif

    #ifndef URPC_NO_EXPORT
        #define URPC_NO_EXPORT
    #endif
#endif

#ifndef URPC_DEPRECATED
    #define URPC_DEPRECATED __declspec(deprecated)
#endif

#ifndef URPC_DEPRECATED_EXPORT
    #define URPC_DEPRECATED_EXPORT URPC_API_EXPORT URPC_DEPRECATED
#endif

#ifndef URPC_DEPRECATED_NO_EXPORT
    #define URPC_DEPRECATED_NO_EXPORT URPC_NO_EXPORT URPC_DEPRECATED
#endif

#if 0 /* DEFINE_NO_DEPRECATED */
    #ifndef URPC_NO_DEPRECATED
        #define URPC_NO_DEPRECATED
    #endif
#endif

#endif
