#
# mod.mk
#

$(MOD)_OBJS     := $(patsubst %.c,$(BUILD)/modules/$(MOD)/%.o,\
	$(filter %.c,$($(MOD)_SRCS)))
$(MOD)_OBJS     += $(patsubst %.cpp,$(BUILD)/modules/$(MOD)/%.o,\
	$(filter %.cpp,$($(MOD)_SRCS)))
$(MOD)_OBJS     += $(patsubst %.S,$(BUILD)/modules/$(MOD)/%.o,\
	$(filter %.S,$($(MOD)_SRCS)))

-include $($(MOD)_OBJS:.o=.d)


ifeq ($(STATIC),)

#
# Dynamically loaded modules
#

$(MOD).so: $($(MOD)_OBJS)
	@echo "  LD  [M] $@"
	@$(CXX) $(LFLAGS) $(SH_LFLAGS) $(MOD_LFLAGS) $($(basename $@)_LFLAGS) \
		$($(basename $@)_LIBS) \
		$(LIBS) $($(basename $@)_OBJS) -o $@

$(BUILD)/modules/$(MOD)/%.o: modules/$(MOD)/%.c $(BUILD) Makefile mk/mod.mk \
				modules/$(MOD)/module.mk mk/modules.mk
	@echo "  CC  [M] $@"
	@mkdir -p $(dir $@)
	@$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@ $(DFLAGS)

$(BUILD)/modules/$(MOD)/%.o: modules/$(MOD)/%.cpp $(BUILD) Makefile mk/mod.mk \
				modules/$(MOD)/module.mk mk/modules.mk
	@echo "  CXX [M] $@"
	@mkdir -p $(dir $@)
	@$(CXX) $(CPPFLAGS) $(CXXFLAGS) -c $< -o $@ $(DFLAGS)

else

#
# Static linking of modules
#

# needed to deref variable now, append to list
OBJS	:= $(OBJS) $($(MOD)_OBJS)
LFLAGS	:= $(LFLAGS) $($(MOD)_LFLAGS)
LIBS	:= $(LIBS) $($(MOD)_LIBS)

$(BUILD)/modules/$(MOD)/%.o: modules/$(MOD)/%.c $(BUILD) Makefile mk/mod.mk \
				modules/$(MOD)/module.mk mk/modules.mk
	@echo "  CC  [m] $@"
	@mkdir -p $(dir $@)
	$(CC) $(CPPFLAGS) $(CFLAGS) -DMOD_NAME=\"$(MOD)\" -c $< \
		-o $@ $(DFLAGS)

$(BUILD)/modules/$(MOD)/%.o: modules/$(MOD)/%.cpp $(BUILD) Makefile mk/mod.mk \
				modules/$(MOD)/module.mk mk/modules.mk
	@echo "  CXX [m] $@"
	@mkdir -p $(dir $@)
	@$(CXX) $(CPPFLAGS) $(CXXFLAGS) -DMOD_NAME=\"$(MOD)\" -c $< \
		-o $@ $(DFLAGS)

endif
