# Harness makefile
# You must pass in MAIN_OFFSET and TARGET_NAME
#
$(TARGET_NAME).dll: dllmain.cpp
	cl /D_USERDLL /D_WINDLL /DMAIN_OFFSET=$(MAIN_OFFSET) dllmain.cpp /MT /link /DLL /OUT:$(TARGET_NAME)_harness.dll

.PHONY: clean
clean:
	del *.dll *.exp *.lib *.obj
