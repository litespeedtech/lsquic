set(docs "${CMAKE_CURRENT_LIST_DIR}/../docs")

foreach(name IN ITEMS
        draft-ietf-webtrans-http3-16
        draft-ietf-webtrans-overview-13
        draft-ietf-webtrans-http2-15
        draft-ietf-quic-reliable-stream-reset-09)
    set(path "${docs}/${name}.txt")
    if(NOT EXISTS "${path}")
        message(FATAL_ERROR "missing draft snapshot: ${path}")
    endif()
    file(READ "${path}" text LIMIT 8192)
    string(FIND "${text}" "${name}" found)
    if(found EQUAL -1)
        message(FATAL_ERROR "wrong embedded draft number in ${path}")
    endif()
endforeach()

foreach(old IN ITEMS
        draft-ietf-webtrans-http3-15.txt
        draft-ietf-quic-reliable-stream-reset-07.txt)
    if(EXISTS "${docs}/${old}")
        message(FATAL_ERROR "superseded draft snapshot remains: ${old}")
    endif()
endforeach()
