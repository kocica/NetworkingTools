cmake_minimum_required(VERSION 3.3)
project(nxp_diagnostic_app)

# show path to extra modules to cmake
set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_SOURCE_DIR}/cmake/modules/" "${CMAKE_SYSROOT}/usr/lib/cmake")
message(INFO "Building package for ${CMAKE_SYSTEM_PROCESSOR}")
find_package(dpdk REQUIRED)

if("${CMAKE_SYSTEM_PROCESSOR}" STREQUAL "armv7l")
	find_package(sring REQUIRED)
	set(DPDK_PMD_LIB_NAME "" CACHE STRING "")	
	set(PLATFORM_LIBS ${DPDK_rte_mempool_ring_LIB} "-lsp1flt -lhwio -ldtree" CACHE STRING "")

elseif("${CMAKE_SYSTEM_PROCESSOR}" STREQUAL "aarch64")
	set(DPDK_PMD_LIB_NAME 
                              ${DPDK_rte_bus_vdev_LIB}
                              ${DPDK_rte_rawdev_LIB}
                              ${DPDK_rte_bus_fslmc_LIB}
                              ${DPDK_rte_mempool_dpaa2_LIB}
                              ${DPDK_rte_pmd_dpaa2_cmdif_LIB}
                              ${DPDK_rte_pmd_skeleton_rawdev_LIB}
                              ${DPDK_rte_pmd_dpaa2_LIB} CACHE STRING "")

	#set(PLATFORM_LIBS ${DPDK_rte_bus_fslmc_LIB} ${DPDK_rte_common_dpaa2_qbman_LIB} ${DPDK_rte_pool_dpaa2_LIB} "-lsp1flt -lhwio -ldtree" CACHE STRING "")

else()
	# x86_64
	set(THREADS_PREFER_PTHREAD_FLAG ON)
	find_package(Numa REQUIRED)
	find_package(dpdk REQUIRED COMPONENTS DPDK_rte_pmd_e1000 REQUIRED)
	set(DPDK_PMD_LIB_NAME ${DPDK_rte_mempool_ring_LIB} ${DPDK_rte_pmd_e1000_LIB} CACHE STRING "")
	set(PLATFORM_LIBS "-lnuma" CACHE STRING "")
endif()


# Find the libraries this project depends upon
find_package(Threads REQUIRED)
#find_package(Boost REQUIRED regex)
find_package(PCAP)
#set(CMAKE_BUILD_TYPE Debug)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -std=c++11 ${DPDK_VECTORIZE_FLAGS}")


# collect all source files
set(project_SRC
  defines.h
  reorder.h
  rx_thread.h
  stats.h
  transport_thread.h
  nxp_diagnostic_app.c
  reorder.c
  rx_thread.c
  stats.c
  transport_thread.c
)

add_executable(nxp_diagnostic_app ${project_SRC} ${PCAP_INCLUDE_DIR})
#target_compile_definitions(nxp_diagnostic_app RIVATE ${EXTRA_DEFINES})



include_directories("${CMAKE_SYSROOT}${DPDK_INCLUDE_DIR}")
target_link_libraries(nxp_diagnostic_app
	-Wl,--whole-archive
	${DPDK_rte_eal_LIB}
	${DPDK_rte_ethdev_LIB}
	${DPDK_rte_ring_LIB}
	${DPDK_rte_mbuf_LIB}
	${DPDK_rte_kvargs_LIB}
	${DPDK_rte_mempool_LIB}
        ${DPDK_rte_hash_LIB}
        ${DPDK_rte_reorder_LIB}
	Threads::Threads ${CMAKE_DL_LIBS}
	${DPDK_PMD_LIB_NAME}
	-Wl,--no-whole-archive
	${PLATFORM_LIBS}
	#${Boost_LIBRARIES}
	${PCAP_LIBRARY}
)


install(TARGETS nxp_diagnostic_app DESTINATION bin)
