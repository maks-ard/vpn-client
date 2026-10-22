package update

import "golang.org/x/sys/windows"

// Исполняемый файл читают и запускают пользователи; изменяют только SYSTEM и
// администраторы. Настройки и скачанные файлы в ProgramData остаются закрытыми.
func prepareExecutable(path string) error {
	sd, err := windows.SecurityDescriptorFromString("D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;GRGX;;;BU)")
	if err != nil {
		return err
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return err
	}
	return windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil)
}
