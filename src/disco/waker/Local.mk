ifdef FD_HAS_HOSTED
$(call add-hdrs,fd_waker.h)
$(call add-objs,fd_waker,fd_disco)
$(call add-objs,fd_waker_tile,fd_disco)
$(call make-unit-test,test_waker,test_waker,fd_disco fd_tango fd_util)
$(call run-unit-test,test_waker)
$(call make-unit-test,test_waker_self_test,test_waker_self_test,fd_util)
$(call run-unit-test,test_waker_self_test)
endif
