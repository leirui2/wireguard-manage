; WireGuard 管理台 —— Inno Setup 6 打包脚本
; 由 build_assets/make_installer.py 调用，不要直接双击（它要传版本号和源目录）
;
; 设计要点：
; 1. 默认 per-user 装到 %LOCALAPPDATA%\Programs，全程不弹 UAC；用户仍可在
;    「选择安装位置」页改成别处，或用命令行 /ALLUSERS 走 Program Files。
; 2. 装到 Program Files 时程序自己会把数据落到 %LOCALAPPDATA%，不会因为
;    写不进安装目录而废掉（见 gui.app_dir 的回退逻辑）。
; 3. 官方客户端 msi 是可选项：build_assets\ 里有就带上，没有就跳过 ——
;    不会因为缺文件编译失败。

#ifndef MyVersion
  #define MyVersion "0.0.0"
#endif
#ifndef SourceDir
  #define SourceDir "..\build\installer-src\WireGuard管理台"
#endif
#ifndef HasWGMSI
  #define HasWGMSI "0"
#endif
#ifndef UseZH
  #define UseZH "0"
#endif
#ifndef ZhFile
  #define ZhFile ""
#endif
#ifndef WGMsiPath
  #define WGMsiPath "wireguard-amd64.msi"
#endif

#define MyAppName "WireGuard 管理台"
#define MyAppExeName "WireGuard管理台.exe"
#define MyAppId "{{9C1D4E7A-3B62-4F18-9A5E-2D7C8B14F603}"

[Setup]
AppId={#MyAppId}
AppName={#MyAppName}
AppVersion={#MyVersion}
AppVerName={#MyAppName} {#MyVersion}
AppPublisher=WireGuard 管理台
AppPublisherURL=https://github.com/leirui2/wireguard-manage
AppSupportURL=https://github.com/leirui2/wireguard-manage/issues
DefaultDirName={autopf}\{#MyAppName}
DefaultGroupName={#MyAppName}
DisableProgramGroupPage=yes
AllowNoIcons=yes
; 默认只给当前用户装，全程不弹 UAC。要给全机装就显式加 /ALLUSERS 参数，
; 不加 dialog —— 那个"仅为我/为所有用户"的选择页对最终用户是多余的一道坎。
PrivilegesRequired=lowest
PrivilegesRequiredOverridesAllowed=commandline
OutputDir=..\dist
#ifndef OutName
  #define OutName "WireGuard管理台-安装包-" + MyVersion
#endif
OutputBaseFilename={#OutName}
SetupIconFile=app.ico
UninstallDisplayIcon={app}\{#MyAppExeName}
UninstallDisplayName={#MyAppName} {#MyVersion}
Compression=lzma2/max
SolidCompression=yes
WizardStyle=modern
; 用 x64 而不是 6.3 才有的 x64compatible，6.2 的编译器也能过
ArchitecturesAllowed=x64
ArchitecturesInstallIn64BitMode=x64
; 覆盖安装时能识别正在运行的旧版本并请用户关掉，而不是报"文件被占用"
CloseApplications=yes
RestartApplications=no
MinVersion=10.0
VersionInfoVersion={#MyVersion}
VersionInfoDescription={#MyAppName} 安装程序
VersionInfoProductName={#MyAppName}

[Languages]
; 中文语言文件是 Inno 的"非官方翻译"，官方安装包不带，所以随仓库放一份
; （build_assets\ChineseSimplified.isl，从 jrsoftware/issrc 的对应 tag 取的）
#if UseZH == "1"
Name: "zh"; MessagesFile: "{#ZhFile}"
#else
Name: "en"; MessagesFile: "compiler:Default.isl"
#endif

[Tasks]
Name: "desktopicon"; Description: "创建桌面快捷方式"; GroupDescription: "附加任务："
#if HasWGMSI == "1"
Name: "wgclient"; Description: "同时安装 WireGuard 官方客户端（组网功能必需，约 3 MB）"; \
    GroupDescription: "附加任务："; Flags: unchecked
#endif

[Files]
Source: "{#SourceDir}\*"; DestDir: "{app}"; \
    Flags: ignoreversion recursesubdirs createallsubdirs; \
    Excludes: "connections.json,tunnels.json,settings.json,known_hosts,traffic.db,audit.jsonl,*.log,updates\*,clients\*,history\*"

#if HasWGMSI == "1"
Source: "{#WGMsiPath}"; DestDir: "{tmp}"; DestName: "wireguard-amd64.msi"; Flags: deleteafterinstall
#endif

[Icons]
Name: "{group}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"
Name: "{group}\卸载 {#MyAppName}"; Filename: "{uninstallexe}"
; 安装目录里也放一个卸载入口。Inno 生成的卸载程序固定叫 unins000.exe，
; 普通人打开文件夹找不到「卸载」两个字就会以为没装卸载程序。
Name: "{app}\卸载 {#MyAppName}"; Filename: "{uninstallexe}"
Name: "{autodesktop}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; Tasks: desktopicon

[Run]
Filename: "{app}\{#MyAppExeName}"; Description: "立即运行 {#MyAppName}"; \
    Flags: nowait postinstall skipifsilent

[UninstallDelete]
; 更新包和导出的客户端配置都是可重建的，卸载时一并清掉；
; 连接配置单独问用户（见 CurUninstallStepChanged）
Type: filesandordirs; Name: "{app}\updates"
Type: filesandordirs; Name: "{app}\__pycache__"

[Code]
var
  RemoveUserData: Boolean;

{ 官方客户端必须提权才能装驱动：用 runas 显式拉起，会弹一次 UAC。
  不用 [Run] 段是因为 per-user 安装时 [Run] 继承的是非提权令牌，
  msiexec 会直接以 1603 失败。 }
function ClientInstalled(): Boolean;
begin
  Result := FileExists(ExpandConstant('{commonpf64}\WireGuard\wireguard.exe')) or
            FileExists(ExpandConstant('{commonpf}\WireGuard\wireguard.exe'));
end;

procedure InstallWireGuardClient();
var
  MsiPath: String;
  ResultCode: Integer;
begin
  { 已经有客户端就什么都不做 —— 升级安装时也走这里，重复装只会多弹一次 UAC }
  if ClientInstalled() then
    Exit;
  MsiPath := ExpandConstant('{tmp}\wireguard-amd64.msi');
  if not FileExists(MsiPath) then
  begin
    MsgBox('没有找到 WireGuard 安装包，跳过。可以装好本程序后手动安装官方客户端。',
           mbInformation, MB_OK);
    Exit;
  end;
  if not ShellExec('runas', 'msiexec.exe',
       '/i "' + MsiPath + '" /qn /norestart DO_NOT_LAUNCH=1',
       '', SW_HIDE, ewWaitUntilTerminated, ResultCode) then
  begin
    MsgBox('安装 WireGuard 客户端需要管理员权限，刚才的授权被取消了。' + #13#10 +
           '本程序仍可正常使用，只是组网功能要等你手动装好客户端。',
           mbInformation, MB_OK);
    Exit;
  end;
  if ResultCode <> 0 then
    MsgBox('WireGuard 客户端安装返回代码 ' + IntToStr(ResultCode) + '。' + #13#10 +
           '可以稍后手动安装，不影响本程序使用。', mbInformation, MB_OK);
end;

procedure CurStepChanged(CurStep: TSetupStep);
begin
  if CurStep = ssPostInstall then
  begin
  #if HasWGMSI == "1"
    if IsTaskSelected('wgclient') then
      InstallWireGuardClient();
  #endif
  end;
end;

{ 卸载时问一次：配置留着还是删掉。
  默认按钮是「否」—— connections.json 里有服务器地址、tunnels.json 里有
  加密过的隧道私钥，误删只能重配。 }
procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
begin
  if CurUninstallStep = usUninstall then
  begin
    if MsgBox('要同时删除本机保存的配置吗？' + #13#10 + #13#10 +
              '包括服务器列表、隧道配置和界面设置（含加密后的口令与私钥）。' + #13#10 +
              '选「否」会保留，重装后可以继续用。',
              mbConfirmation, MB_YESNO or MB_DEFBUTTON2) = IDYES then
      RemoveUserData := True
    else
      RemoveUserData := False;
  end;

  if CurUninstallStep = usPostUninstall then
  begin
    if RemoveUserData then
    begin
      DeleteFile(ExpandConstant('{app}\connections.json'));
      DeleteFile(ExpandConstant('{app}\tunnels.json'));
      DeleteFile(ExpandConstant('{app}\settings.json'));
      DeleteFile(ExpandConstant('{app}\known_hosts'));
      DeleteFile(ExpandConstant('{app}\traffic.db'));
      DelTree(ExpandConstant('{app}\clients'), True, True, True);
      DelTree(ExpandConstant('{app}\history'), True, True, True);
      { 装到 Program Files 时数据在 %LOCALAPPDATA%，那里也要清 }
      DelTree(ExpandConstant('{localappdata}\WireGuard管理台'), True, True, True);
    end;
  end;
end;
