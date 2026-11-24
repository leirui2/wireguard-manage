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
#define MyAppGuid "9C1D4E7A-3B62-4F18-9A5E-2D7C8B14F603"
#define MyAppId "{{" + MyAppGuid + "}"
; 客户端勾选项的描述文案：必须无条件定义。
; 之前放在 [Tasks] 的 #if HasWGMSI == "1" 里，CI 上没带 msi（HasWGMSI=0）时
; 这个 #define 被跳过，[Code] 里的 '{#WgTaskDesc}' 就成了未声明标识符，编译失败。
#define WgTaskDesc "同时安装 WireGuard 官方客户端（组网功能必需，约 3 MB）"

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
; 「选择安装位置」页必须每次都显示。
; Inno 的默认值是 auto —— 一旦发现上次装过的目录就直接跳过这一页，
; 沿用旧路径（UsePreviousAppDir 的默认行为）。结果就是升级时想把程序
; 从 D:\Program Files 挪回默认目录、或者换个盘，都没机会改。
; 显式写 no：升级时这一页照样出现，路径预填上次的目录，用户随时可改。
DisableDirPage=no
; 上一版装在哪个目录，就默认填哪个目录（覆盖安装时用户不用再找路径）。
UsePreviousAppDir=yes
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
Name: "wgclient"; Description: "{#WgTaskDesc}"; \
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
  DirHint: TNewStaticText;
  WgHint: TNewStaticText;
  WgTaskInit: Boolean;

{ ---------- 通用小工具 ---------- }

{ 取注册表字符串：先试 Root1，没有再试 Root2。 }
function RegStr(Root1, Root2: Integer; const SubKey, ValueName: String): String;
var
  V: String;
begin
  Result := '';
  if RegQueryStringValue(Root1, SubKey, ValueName, V) then
    Result := V
  else if RegQueryStringValue(Root2, SubKey, ValueName, V) then
    Result := V;
end;

{ 截掉末尾的反斜杠，否则拼路径会出现双斜杠。 }
function StripSlash(S: String): String;
begin
  Result := S;
  while (Length(Result) > 1) and (Result[Length(Result)] = '\') do
    Delete(Result, Length(Result), 1);
end;

{ Pascal Script 不支持嵌套函数，拆成两个顶层函数。 }
function VerNumAt(const S: String; var P: Integer): Integer;
var
  T: String;
begin
  T := '';
  while (P <= Length(S)) and (S[P] <> '.') do
  begin
    T := T + S[P];
    Inc(P);
  end;
  if (P <= Length(S)) and (S[P] = '.') then
    Inc(P);
  Result := StrToIntDef(T, 0);
end;

{ 版本号比较：1.0.26 vs 1.0.27。返回 -1 / 0 / 1；非数字段当 0。 }
function CompareVer(A, B: String): Integer;
var
  I, NA, NB, PA, PB: Integer;
begin
  Result := 0;
  PA := 1;
  PB := 1;
  for I := 1 to 4 do
  begin
    NA := VerNumAt(A, PA);
    NB := VerNumAt(B, PB);
    if NA <> NB then
    begin
      if NA > NB then
        Result := 1
      else
        Result := -1;
      Exit;
    end;
  end;
end;

{ ---------- 已装版本探测 ---------- }

function UninstallKey(): String;
begin
  { 左花括号要放进字符串里写，直接写在代码里会被当注释开头；
    行首也不能以 # 开头，否则 ISPP 会当成预处理指令。 }
  Result := 'Software\Microsoft\Windows\CurrentVersion\Uninstall\' +
            '{' + '{#MyAppGuid}' + '}_is1';
end;

{ 上一个版本装在哪。空串 = 这台机器没装过。 }
function ExistingDir(): String;
var
  D: String;
begin
  D := StripSlash(RegStr(HKCU, HKLM, UninstallKey(), 'InstallLocation'));
  if (D <> '') and FileExists(D + '\{#MyAppExeName}') then
    Result := D
  else
    Result := '';
end;

function ExistingVersion(): String;
begin
  Result := RegStr(HKCU, HKLM, UninstallKey(), 'DisplayVersion');
end;

{ ---------- 官方客户端探测 ---------- }

function ClientPath(): String;
begin
  Result := ExpandConstant('{commonpf64}\WireGuard\wireguard.exe');
  if not FileExists(Result) then
    Result := ExpandConstant('{commonpf}\WireGuard\wireguard.exe');
  if not FileExists(Result) then
    Result := '';
end;

{ 官方客户端版本号（文件版本 1.1.1 这种），取不到返回空串。 }
function ClientVersionStr(): String;
var
  P: String;
  MS, LS: Cardinal;
begin
  Result := '';
  P := ClientPath();
  if P = '' then
    Exit;
  if GetVersionNumbers(P, MS, LS) then
    Result := Format('%d.%d', [MS shr 16, MS and $FFFF]);
end;

{ ---------- 向导界面提示 ---------- }

procedure BuildDirHint();
var
  Old, OldVer: String;
  Text: String;
begin
  Old := ExistingDir();
  if Old = '' then
  begin
    DirHint.Visible := False;
    Exit;
  end;

  OldVer := ExistingVersion();
  if OldVer = '' then
    OldVer := '旧版本';

  if CompareVer(OldVer, '{#MyVersion}') < 0 then
    Text := '检测到已安装 ' + OldVer + '，本次为升级安装。'
  else if CompareVer(OldVer, '{#MyVersion}') = 0 then
    Text := '检测到本版本已安装过，本次为覆盖安装。'
  else
    Text := '检测到已安装更高的 ' + OldVer + '，继续会降级覆盖。';

  DirHint.Caption := Text + #13#10 +
    '将装到 ' + Old + '，服务器列表、隧道和密钥都会保留。' + #13#10 +
    '要换目录请先卸载旧版本，否则会留下两份。';
  DirHint.Visible := True;
end;

procedure BuildWgHint();
var
  Idx, I, T: Integer;
  Ver: String;
begin
  { 位置在这里算：InitializeWizard 时页面还没排版，各项 Height 都是 0，
    算出来的 Top 会把提示顶到看不见的地方。 }
  T := WizardForm.TasksList.Top + WizardForm.TasksList.Height + ScaleY(8);
  if T + WgHint.Height > WizardForm.SelectTasksPage.Height then
    T := WizardForm.SelectTasksPage.Height - WgHint.Height - ScaleY(4);
  if T < 0 then
    T := 0;
  WgHint.Top := T;
  WgHint.BringToFront;

  Ver := ClientVersionStr();
  if Ver <> '' then
  begin
    WgHint.Caption := '已检测到 WireGuard 官方客户端 ' + Ver + '，这一项不用勾，' +
      '勾了也只会跳过。';
    WgHint.Font.Color := clGray;
    { 已装就把勾去掉、并置灰，避免用户重复选 }
    for I := 0 to WizardForm.TasksList.Items.Count - 1 do
      if WizardForm.TasksList.Items[I] = '{#WgTaskDesc}' then
      begin
        WizardForm.TasksList.Checked[I] := False;
        WizardForm.TasksList.ItemEnabled[I] := False;
      end;
  end
  else
  begin
    WgHint.Caption := '未检测到 WireGuard 官方客户端。组网功能需要它，' +
      '已默认勾选；安装时会弹一次 UAC 授权。';
    WgHint.Font.Color := clMaroon;
    if not WgTaskInit then
      for I := 0 to WizardForm.TasksList.Items.Count - 1 do
        if WizardForm.TasksList.Items[I] = '{#WgTaskDesc}' then
          WizardForm.TasksList.Checked[I] := True;
  end;
  WgTaskInit := True;
  WgHint.Visible := True;
end;

procedure InitializeWizard();
begin
  WgTaskInit := False;

  { 安装位置页：说明「检测到已装」+ 会覆盖到哪个目录 }
  DirHint := TNewStaticText.Create(WizardForm);
  DirHint.Parent := WizardForm.SelectDirPage;
  DirHint.AutoSize := False;
  DirHint.WordWrap := True;
  DirHint.Left := WizardForm.DirEdit.Left;
  DirHint.Width := WizardForm.DirEdit.Width + WizardForm.DirBrowseButton.Width + ScaleX(8);
  DirHint.Height := ScaleY(86);
  DirHint.Top := WizardForm.DiskSpaceLabel.Top - DirHint.Height - ScaleY(8);
  DirHint.Font.Color := clMaroon;
  DirHint.Visible := False;

  { 附加任务页：说明官方客户端装没装、要不要勾 }
  WgHint := TNewStaticText.Create(WizardForm);
  WgHint.Parent := WizardForm.SelectTasksPage;
  WgHint.AutoSize := False;
  WgHint.WordWrap := True;
  WgHint.Left := WizardForm.TasksList.Left;
  WgHint.Width := WizardForm.TasksList.Width;
  WgHint.Height := ScaleY(62);
  { 贴页面底部；任务列表太高时再往上让，避免压住列表 }
  WgHint.Top := WizardForm.SelectTasksPage.Height - WgHint.Height - ScaleY(10);
  if WgHint.Top < WizardForm.TasksList.Top + WizardForm.TasksList.Height + ScaleY(6) then
    WgHint.Top := WizardForm.TasksList.Top + WizardForm.TasksList.Height + ScaleY(6);
  WgHint.Visible := False;
end;

procedure CurPageChanged(CurPageID: Integer);
begin
  case CurPageID of
    wpSelectDir:
      BuildDirHint();
  #if HasWGMSI == "1"
    wpSelectTasks:
      BuildWgHint();
  #endif
  end;
end;

{ 官方客户端必须提权才能装驱动：用 runas 显式拉起，会弹一次 UAC。
  不用 [Run] 段是因为 per-user 安装时 [Run] 继承的是非提权令牌，
  msiexec 会直接以 1603 失败。 }
function ClientInstalled(): Boolean;
begin
  Result := ClientPath() <> '';
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
