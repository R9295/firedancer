ifdef FD_HAS_HOSTED
ifdef FD_HAS_LINUX

.PHONY: firedancer-cluster

$(call make-bin,firedancer-cluster,main,fd_util)

$(call make-unit-test,test_firedancer_cluster,tests/test_firedancer_cluster,fd_util)
$(OBJDIR)/unit-test/test_firedancer_cluster: $(OBJDIR)/bin/firedancer-cluster
$(call run-unit-test,test_firedancer_cluster)

endif
endif
