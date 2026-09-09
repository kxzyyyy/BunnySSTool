Add-Type -AssemblyName PresentationFramework
Add-Type -AssemblyName PresentationCore
Add-Type -AssemblyName WindowsBase
Add-Type -AssemblyName System.Xaml
Add-Type -AssemblyName System.Windows.Forms

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$script:ScriptDir   = Split-Path -Parent $MyInvocation.MyCommand.Path
$script:RepoRawUrl  = "https://raw.githubusercontent.com/kxzyyyy/BunnySSTool/main"
$script:InstallDir  = "$env:USERPROFILE\Downloads\BunnySSTool"

$ToolData = @(
    @{ Name="BAMReveal";            Desc="Reveals programs run from the Background Activity Moderator";  Category="Orbdiff";     Type="EXE";     URL="https://github.com/Orbdiff/BAMReveal/releases/latest" },
    @{ Name="StringsParser";        Desc="Scans binaries for strings, YARA rules, and known signatures"; Category="Orbdiff";     Type="EXE";     URL="https://github.com/Orbdiff/StringsParser/releases/latest" },
    @{ Name="INJgen";               Desc="Spots JNI and JVMTI-based memory injection techniques";        Category="Orbdiff";     Type="EXE";     URL="https://github.com/Orbdiff/InjGen/releases/latest" },
    @{ Name="Fileless";             Desc="Hunts fileless execution through event logs and memory dumps";  Category="Orbdiff";     Type="EXE";     URL="https://github.com/Orbdiff/Fileless/releases/latest" },
    @{ Name="JARParser";            Desc="Inspects JAR prefetch data and DcomLaunch string references";   Category="Orbdiff";     Type="EXE";     URL="https://github.com/Orbdiff/JARParser/releases/latest" },
    @{ Name="CheckDeletedUSN";      Desc="Cross-references USN deletion times against last boot timestamp"; Category="Orbdiff";   Type="EXE";     URL="https://github.com/Orbdiff/CheckDeletedUSN/releases/latest" },
    @{ Name="USBDetector";          Desc="Enumerates past USB device connections and mount history";      Category="Orbdiff";     Type="EXE";     URL="https://github.com/Orbdiff/USBDetector/releases/latest" },
    @{ Name="BAMDeletedKeys";       Desc="Recovers removed BAM registry entries to find wiped traces";    Category="Spokwn";      Type="EXE";     URL="https://github.com/spokwn/BamDeletedKeys/releases/latest" },
    @{ Name="pcasvc-executed";      Desc="Pulls Program Compatibility Assistant execution logs";          Category="Spokwn";      Type="EXE";     URL="https://github.com/spokwn/pcasvc-executed/releases/latest" },
    @{ Name="MeowClientFucker";     Desc="Flags known modified cheat clients and their leftovers";        Category="MeowTonynoh"; Type="EXE";     URL="https://github.com/MeowTonynoh/MeowClientFucker/releases/latest" },
    @{ Name="MeowModAnalyzer";      Desc="Scans mod files for hidden or tampered code";                   Category="MeowTonynoh"; Type="Powershell"; Command="Invoke-Expression (Invoke-RestMethod 'https://raw.githubusercontent.com/MeowTonynoh/MeowModAnalyzer/main/MeowModAnalyzer.ps1')" },
    @{ Name="MeowResolver";         Desc="Deobfuscates encoded strings inside compiled binaries";         Category="MeowTonynoh"; Type="EXE";     URL="https://github.com/MeowTonynoh/MeowResolver/releases/latest" },
    @{ Name="Services";             Desc="Enumerates and reviews all active Windows services";           Category="PraiseLilly"; Type="Powershell"; Command="Invoke-Expression (Invoke-RestMethod 'https://raw.githubusercontent.com/praiselily/lilith-ps/refs/heads/main/Services.ps1')" },
    @{ Name="RL ModAnalyzer";       Desc="Reviews mod archives for tampering and cheat hooks";            Category="RedLotus";    Type="EXE";     URL="https://github.com/ItzIceHere/RedLotus-Mod-Analyzer/releases/latest" },
    @{ Name="RL AltChecker";        Desc="Looks for signs of alternate or smurf accounts on the PC";      Category="RedLotus";    Type="EXE";     URL="https://github.com/ItzIceHere/RedLotusAltChecker/releases/latest" },
    @{ Name="P1AE.Javaw";           Desc="Watches Java processes in real time (v1.12 by p1aegg)";         Category="Others";      Type="EXE";     URL="https://github.com/p1aegg/javaw/releases/download/v1.12/P1AE.Javaw.exe" },
    @{ Name="MacroDetector";        Desc="Traces leftover macro and auto-clicker footprints";             Category="Others";      Type="Powershell"; Command="Invoke-Expression (Invoke-RestMethod 'https://raw.githubusercontent.com/NiccBlahh/MacroDetector/refs/heads/main/MacroDetector.ps1')" },
    @{ Name="DQRKIS-Fucker";        Desc="Searches for DQRKIS-specific cheat remnants";                   Category="Others";      Type="Powershell"; Command="Invoke-Expression (Invoke-RestMethod 'https://raw.githubusercontent.com/cheesecatlol/DQRKIS-FUCKER/refs/heads/main/DqrkisFucker.ps1')" },
    @{ Name="SystemInformer";       Desc="In-depth process, handle, and kernel-level explorer";          Category="Others";      Type="Link";    URL="https://www.systeminformer.com/canary" },
    @{ Name="Luyten";               Desc="Java reverse-engineering GUI built on the Procyon engine";      Category="Others";      Type="EXE";     URL="https://github.com/deathmarine/Luyten/releases/latest" },
    @{ Name="ToolsDownloader++";    Desc="All-in-one downloader for popular SS checking utilities";       Category="Others";      Type="Link";    URL="https://detect.ac/tool/ToolsDownloader++" }
)

$Categories = @("All","Orbdiff","Spokwn","MeowTonynoh","PraiseLilly","RedLotus","Others")

function Get-AssetPath {
    param([string]$Name)
    if ($script:ScriptDir) {
        $p = Join-Path $script:ScriptDir "assets\$Name"
        if (Test-Path -LiteralPath $p) { return $p }
    }
    return "$script:RepoRawUrl/assets/$Name"
}

function New-ImageBrush {
    param([string]$Path, [double]$Opacity = 1.0)
    if (-not $Path) { return $null }
    try {
        $img = New-Object System.Windows.Media.Imaging.BitmapImage
        $img.BeginInit()
        $img.CacheOption = [System.Windows.Media.Imaging.BitmapCacheOption]::OnLoad
        $img.UriSource   = [Uri]::new($Path)
        $img.EndInit()
        $img.Freeze()
        $brush = New-Object System.Windows.Media.ImageBrush $img
        $brush.Stretch    = [System.Windows.Stretch]::UniformToFill
        $brush.AlignmentX = [System.Windows.Alignment]::Center
        $brush.AlignmentY = [System.Windows.Alignment]::Center
        $brush.Opacity    = $Opacity
        return $brush
    } catch { return $null }
}

function New-BitmapImage {
    param([string]$Path)
    if (-not $Path) { return $null }
    try {
        $img = New-Object System.Windows.Media.Imaging.BitmapImage
        $img.BeginInit()
        $img.CacheOption = [System.Windows.Media.Imaging.BitmapCacheOption]::OnLoad
        $img.UriSource   = [Uri]::new($Path)
        $img.EndInit()
        $img.Freeze()
        return $img
    } catch { return $null }
}

[xml]$disclaimerXaml = @"
<Window
    xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
    xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
    Title="BunnySSTool"
    Width="560" Height="620"
    WindowStartupLocation="CenterScreen"
    ResizeMode="NoResize"
    WindowStyle="None"
    AllowsTransparency="True"
    Background="Transparent"
    FontFamily="Segoe UI">

    <Border x:Name="Root" BorderBrush="#202943" BorderThickness="1" CornerRadius="14" Padding="0">
        <Border.Background>
            <LinearGradientBrush StartPoint="0,0" EndPoint="0.7,1">
                <GradientStop Color="#0B1020" Offset="0"/>
                <GradientStop Color="#0D1326" Offset="0.5"/>
                <GradientStop Color="#101830" Offset="1"/>
            </LinearGradientBrush>
        </Border.Background>
        <Border.Effect>
            <DropShadowEffect Color="#8B7FC7" BlurRadius="30" ShadowDepth="0" Opacity="0.2"/>
        </Border.Effect>

        <Grid Margin="36,30,36,28">
            <Grid.RowDefinitions>
                <RowDefinition Height="Auto"/>
                <RowDefinition Height="Auto"/>
                <RowDefinition Height="*"/>
                <RowDefinition Height="Auto"/>
            </Grid.RowDefinitions>

            <StackPanel Grid.Row="0" HorizontalAlignment="Center" Margin="0,0,0,18">
                <Border Width="84" Height="84" CornerRadius="42" Padding="0">
                    <Border.Background>
                        <RadialGradientBrush>
                            <GradientStop Color="#202943" Offset="0"/>
                            <GradientStop Color="#0B1020" Offset="1"/>
                        </RadialGradientBrush>
                    </Border.Background>
                    <Border.BorderBrush><SolidColorBrush Color="#8B7FC7" Opacity="0.6"/></Border.BorderBrush>
                    <Border.BorderThickness>1.5</Border.BorderThickness>
                    <Grid>
                        <Image x:Name="DisclaimerIconImg" Width="56" Height="56" Stretch="Uniform" Visibility="Collapsed" VerticalAlignment="Center" HorizontalAlignment="Center"/>
                        <TextBlock x:Name="DisclaimerAsciiBunny" Text="(\(\&#x0a;( -.-)&#x0a;(__(`)" FontFamily="Consolas" FontSize="13"
                                   Foreground="#BFC7E8" HorizontalAlignment="Center" VerticalAlignment="Center"
                                   TextAlignment="Center"/>
                    </Grid>
                </Border>
            </StackPanel>

            <TextBlock Grid.Row="1" Text="BunnySSTool" FontSize="26" FontWeight="Bold"
                       Foreground="#E8E7ED" HorizontalAlignment="Center" Margin="0,0,0,6"/>
            <TextBlock Grid.Row="1" Text="思春期症候群 · Adolescence Syndrome" FontSize="11"
                       Foreground="#8B7FC7" HorizontalAlignment="Center" Margin="0,40,0,0"/>

            <Border Grid.Row="2" Background="#151C30" CornerRadius="10" Padding="20,16" Margin="0,18,0,18">
                <Border.BorderBrush><SolidColorBrush Color="#202943" Opacity="0.8"/></Border.BorderBrush>
                <StackPanel>
                    <TextBlock TextWrapping="Wrap" Foreground="#E8E7ED" FontSize="12.5" Margin="0,0,0,12"
                               LineHeight="20"
                               Text="All programs are downloaded automatically from their official GitHub repositories or author-hosted sources and saved in a neatly organized folder. None of your information is ever collected or modified."/>
                    <TextBlock TextWrapping="Wrap" Foreground="#E8E7ED" FontSize="12.5" Margin="0,0,0,12"
                               LineHeight="20"
                               Text="Each tool is developed and maintained by its own author. BunnySSTool only fetches and launches them. I take no responsibility for anything that may be found regarding these tools in the future."/>
                    <Border Background="#202943" CornerRadius="6" Padding="12,8" Margin="0,4,0,0">
                        <TextBlock TextWrapping="Wrap" Foreground="#BFC7E8" FontSize="12" FontWeight="SemiBold"
                                   Text="By continuing you agree with everything stated above."/>
                    </Border>
                </StackPanel>
            </Border>

            <Grid Grid.Row="3">
                <Grid.ColumnDefinitions>
                    <ColumnDefinition Width="*"/>
                    <ColumnDefinition Width="14"/>
                    <ColumnDefinition Width="*"/>
                </Grid.ColumnDefinitions>
                <Button x:Name="CancelBtn" Grid.Column="0" Content="Cancel" Height="44"
                        Cursor="Hand" FontSize="13">
                    <Button.Template>
                        <ControlTemplate TargetType="Button">
                            <Border x:Name="CbBd" Background="Transparent" BorderBrush="#202943" BorderThickness="1" CornerRadius="8">
                                <ContentPresenter HorizontalAlignment="Center" VerticalAlignment="Center"/>
                            </Border>
                            <ControlTemplate.Triggers>
                                <Trigger Property="IsMouseOver" Value="True">
                                    <Setter TargetName="CbBd" Property="Background" Value="#202943"/>
                                </Trigger>
                            </ControlTemplate.Triggers>
                        </ControlTemplate>
                    </Button.Template>
                    <Button.Foreground><SolidColorBrush Color="#E8E7ED"/></Button.Foreground>
                </Button>
                <Button x:Name="AcceptBtn" Grid.Column="2" Content="Accept &amp; Continue" Height="44"
                        Cursor="Hand" FontSize="13" FontWeight="SemiBold">
                    <Button.Template>
                        <ControlTemplate TargetType="Button">
                            <Border x:Name="AbBd" Background="#202943" BorderBrush="#8B7FC7" BorderThickness="1" CornerRadius="8">
                                <ContentPresenter HorizontalAlignment="Center" VerticalAlignment="Center"/>
                            </Border>
                            <ControlTemplate.Triggers>
                                <Trigger Property="IsMouseOver" Value="True">
                                    <Setter TargetName="AbBd" Property="Background" Value="#2A3450"/>
                                </Trigger>
                            </ControlTemplate.Triggers>
                        </ControlTemplate>
                    </Button.Template>
                    <Button.Foreground><SolidColorBrush Color="#BFC7E8"/></Button.Foreground>
                </Button>
            </Grid>
        </Grid>
    </Border>
</Window>
"@

$disclaimerReader = New-Object System.Xml.XmlNodeReader $disclaimerXaml
$disclaimerWindow = [Windows.Markup.XamlReader]::Load($disclaimerReader)
$disclaimerWindow.Add_MouseLeftButtonDown({ try { $disclaimerWindow.DragMove() } catch {} })

$disclaimerRoot = $disclaimerWindow.FindName("Root")
$bgImg = Get-AssetPath "bg.png"
if ($bgImg) {
    $b = New-ImageBrush $bgImg 0.12
    if ($b) { $disclaimerRoot.Background = $b }
}

$hairclipPath = Get-AssetPath "BunnnyHairclipFavicon.png"
if ($hairclipPath) {
    try {
        $iconBmp = New-BitmapImage $hairclipPath
        if ($iconBmp) {
            $discIconImg = $disclaimerWindow.FindName("DisclaimerIconImg")
            $discAscii   = $disclaimerWindow.FindName("DisclaimerAsciiBunny")
            if ($discIconImg) {
                $discIconImg.Source = $iconBmp
                $discIconImg.Visibility = [System.Windows.Visibility]::Visible
            }
            if ($discAscii) { $discAscii.Visibility = [System.Windows.Visibility]::Collapsed }
        }
    } catch {}
}

$CancelBtn = $disclaimerWindow.FindName("CancelBtn")
$AcceptBtn = $disclaimerWindow.FindName("AcceptBtn")
$script:disclaimerAccepted = $false
$AcceptBtn.Add_Click({ $script:disclaimerAccepted = $true; $disclaimerWindow.Close() })
$CancelBtn.Add_Click({ $script:disclaimerAccepted = $false; $disclaimerWindow.Close() })
$disclaimerWindow.ShowDialog() | Out-Null
if (-not $script:disclaimerAccepted) { exit }

$gifPath = Get-AssetPath "mai-dancing.gif"
if ($gifPath) {
    Add-Type -AssemblyName System.Drawing

    if ($gifPath -match "^https?://") {
        $gifTemp = [System.IO.Path]::Combine($env:TEMP, "bunny_mai-dancing.gif")
        try {
            $wc = New-Object System.Net.WebClient
            $wc.Headers.Add("User-Agent", "BunnySSTool")
            $wc.DownloadFile($gifPath, $gifTemp)
            $gifPath = $gifTemp
        } catch { $gifPath = $null }
    }

    if ($gifPath -and (Test-Path -LiteralPath $gifPath)) {
        $gifBitmap = New-Object System.Drawing.Bitmap($gifPath)
    $frameCount = $gifBitmap.GetFrameCount([System.Drawing.Imaging.FrameDimension]::Time)

    $frameDelays = @()
    try {
        $delayProp = $gifBitmap.GetPropertyItem(0x5100)
        for ($i = 0; $i -lt $frameCount; $i++) {
            $delay = [BitConverter]::ToInt32($delayProp.Value, $i * 4)
            if ($delay -le 0) { $delay = 10 }
            $frameDelays += $delay * 10
        }
    } catch {
        for ($i = 0; $i -lt $frameCount; $i++) { $frameDelays += 100 }
    }

    $gifFrameSources = @()
    for ($i = 0; $i -lt $frameCount; $i++) {
        $gifBitmap.SelectActiveFrame([System.Drawing.Imaging.FrameDimension]::Time, $i) | Out-Null
        $hbitmap = $gifBitmap.GetHbitmap()
        $source = [System.Windows.Interop.Imaging]::CreateBitmapSourceFromHBitmap(
            $hbitmap, [IntPtr]::Zero, [System.Windows.Int32Rect]::Empty,
            [System.Windows.Media.Imaging.BitmapSizeOptions]::FromEmptyOptions())
        $source.Freeze()
        $gifFrameSources += $source
    }
    $gifBitmap.Dispose()

    [xml]$loadXaml = @"
<Window
    xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
    xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
    Title="BunnySSTool"
    Width="500" Height="560"
    WindowStartupLocation="CenterScreen"
    ResizeMode="NoResize"
    WindowStyle="None"
    AllowsTransparency="True"
    Background="Transparent"
    FontFamily="Segoe UI">

    <Border x:Name="LoadRoot" CornerRadius="14" BorderBrush="#202943" BorderThickness="1" ClipToBounds="True">
        <Border.Effect>
            <DropShadowEffect Color="#000000" BlurRadius="24" ShadowDepth="0" Opacity="0.5"/>
        </Border.Effect>

        <Grid x:Name="LoadContent">
            <Image x:Name="GifImage" Stretch="UniformToFill" Opacity="0.6">
                <Image.Effect>
                    <BlurEffect Radius="8"/>
                </Image.Effect>
            </Image>
            <Border Background="#0B1020" Opacity="0.4"/>

            <TextBlock Text="BunnySSTool" FontSize="26" FontWeight="Bold"
                       Foreground="#E8E7ED" HorizontalAlignment="Center" VerticalAlignment="Top" Margin="0,32,0,0"/>
            <TextBlock Text="Loading..." FontSize="12"
                       Foreground="#BFC7E8" HorizontalAlignment="Center" VerticalAlignment="Top" Margin="0,66,0,0"/>

            <Grid Width="64" Height="64" HorizontalAlignment="Center" VerticalAlignment="Center">
                <Ellipse Width="64" Height="64" Stroke="#202943" StrokeThickness="4" Fill="Transparent"/>
                <Ellipse Width="64" Height="64" Stroke="#8B7FC7" StrokeThickness="4" Fill="Transparent"
                         StrokeDashArray="45,140" StrokeDashCap="Round" RenderTransformOrigin="0.5,0.5">
                    <Ellipse.RenderTransform>
                        <RotateTransform x:Name="SpinnerRotate" Angle="0"/>
                    </Ellipse.RenderTransform>
                </Ellipse>
            </Grid>
        </Grid>
    </Border>
</Window>
"@

    $loadReader = New-Object System.Xml.XmlNodeReader $loadXaml
    $loadWindow = [Windows.Markup.XamlReader]::Load($loadReader)

    $GifImage      = $loadWindow.FindName("GifImage")
    $SpinnerRotate = $loadWindow.FindName("SpinnerRotate")
    $LoadContent   = $loadWindow.FindName("LoadContent")

    $rotateAnim = New-Object System.Windows.Media.Animation.DoubleAnimation
    $rotateAnim.From = 0
    $rotateAnim.To = 360
    $rotateAnim.Duration = [TimeSpan]::FromMilliseconds(700)
    $rotateAnim.RepeatBehavior = [System.Windows.Media.Animation.RepeatBehavior]::Forever
    $SpinnerRotate.BeginAnimation([System.Windows.Media.RotateTransform]::AngleProperty, $rotateAnim)

    if ($gifFrameSources.Count -gt 0) {
        $GifImage.Source = $gifFrameSources[0]
    }
    $script:frameIdx = 0
    $frameTimer = New-Object System.Windows.Threading.DispatcherTimer
    $frameTimer.Interval = [TimeSpan]::FromMilliseconds($frameDelays[0])
    $frameTimer.Add_Tick({
        $script:frameIdx = ($script:frameIdx + 1) % $gifFrameSources.Count
        $GifImage.Source = $gifFrameSources[$script:frameIdx]
        $frameTimer.Interval = [TimeSpan]::FromMilliseconds($frameDelays[$script:frameIdx])
    })

    $progressTimer = New-Object System.Windows.Threading.DispatcherTimer
    $progressTimer.Interval = [TimeSpan]::FromMilliseconds(30)
    $script:loadProgress = 0
    $progressTimer.Add_Tick({
        $script:loadProgress += 1
        if ($script:loadProgress -ge 100) {
            $progressTimer.Stop()
            $frameTimer.Stop()

            $targetW = 1280
            $targetH = 800
            $targetLeft = $loadWindow.Left - ($targetW - $loadWindow.Width) / 2
            $targetTop  = $loadWindow.Top  - ($targetH - $loadWindow.Height) / 2
            $animDur = [TimeSpan]::FromMilliseconds(500)
            $ease = New-Object System.Windows.Media.Animation.CubicEase
            $ease.EasingMode = [System.Windows.Media.Animation.EasingMode]::EaseOut

            $wAnim = New-Object System.Windows.Media.Animation.DoubleAnimation($targetW, $animDur)
            $wAnim.EasingFunction = $ease
            $hAnim = New-Object System.Windows.Media.Animation.DoubleAnimation($targetH, $animDur)
            $hAnim.EasingFunction = $ease
            $lAnim = New-Object System.Windows.Media.Animation.DoubleAnimation($targetLeft, $animDur)
            $lAnim.EasingFunction = $ease
            $tAnim = New-Object System.Windows.Media.Animation.DoubleAnimation($targetTop, $animDur)
            $tAnim.EasingFunction = $ease
            $fadeAnim = New-Object System.Windows.Media.Animation.DoubleAnimation(0, $animDur)

            $wAnim.Add_Completed({ $loadWindow.Close() })

            $loadWindow.BeginAnimation([System.Windows.Window]::WidthProperty, $wAnim)
            $loadWindow.BeginAnimation([System.Windows.Window]::HeightProperty, $hAnim)
            $loadWindow.BeginAnimation([System.Windows.Window]::LeftProperty, $lAnim)
            $loadWindow.BeginAnimation([System.Windows.Window]::TopProperty, $tAnim)
            $LoadContent.BeginAnimation([System.Windows.FrameworkElement]::OpacityProperty, $fadeAnim)
        }
    })

    $loadWindow.Add_Loaded({
        $frameTimer.Start()
        $progressTimer.Start()
    })
    $loadWindow.ShowDialog() | Out-Null
    }
}

[xml]$xaml = @"
<Window
    xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
    xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
    Title="BunnySSTool"
    Width="1280" Height="800"
    MinWidth="1280" MinHeight="800"
    WindowStartupLocation="CenterScreen"
    ResizeMode="NoResize"
    WindowStyle="None"
    AllowsTransparency="True"
    Background="Transparent"
    FontFamily="Segoe UI">

    <Window.Resources>
        <SolidColorBrush x:Key="DeepBg"     Color="#0B1020"/>
        <SolidColorBrush x:Key="Surface"    Color="#151C30"/>
        <SolidColorBrush x:Key="Elevated"   Color="#202943"/>
        <SolidColorBrush x:Key="Accent"     Color="#8B7FC7"/>
        <SolidColorBrush x:Key="Accent2"    Color="#D98FA8"/>
        <SolidColorBrush x:Key="Highlight"  Color="#BFC7E8"/>
        <SolidColorBrush x:Key="TextMain"   Color="#E8E7ED"/>
        <SolidColorBrush x:Key="TextMuted"  Color="#858BA3"/>
        <SolidColorBrush x:Key="TextDim"    Color="#5A6080"/>
        <SolidColorBrush x:Key="ConsoleBg"  Color="#080D1A"/>

        <Style x:Key="CatPill" TargetType="RadioButton">
            <Setter Property="Foreground" Value="{StaticResource TextMuted}"/>
            <Setter Property="FontSize" Value="11"/>
            <Setter Property="Cursor" Value="Hand"/>
            <Setter Property="Margin" Value="0,3"/>
            <Setter Property="HorizontalAlignment" Value="Stretch"/>
            <Setter Property="Template">
                <Setter.Value>
                    <ControlTemplate TargetType="RadioButton">
                        <Border x:Name="Pill" Background="Transparent" CornerRadius="7" Padding="12,9">
                            <Grid>
                                <Grid.ColumnDefinitions>
                                    <ColumnDefinition Width="3"/>
                                    <ColumnDefinition Width="8"/>
                                    <ColumnDefinition Width="*"/>
                                </Grid.ColumnDefinitions>
                                <Border x:Name="Dot" Grid.Column="0" Width="3" CornerRadius="2" Background="Transparent" VerticalAlignment="Stretch"/>
                                <ContentPresenter Grid.Column="2" VerticalAlignment="Center"/>
                            </Grid>
                        </Border>
                        <ControlTemplate.Triggers>
                            <Trigger Property="IsMouseOver" Value="True">
                                <Setter TargetName="Pill" Property="Background" Value="#202943"/>
                                <Setter Property="Foreground" Value="#E8E7ED"/>
                            </Trigger>
                            <Trigger Property="IsChecked" Value="True">
                                <Setter TargetName="Pill" Property="Background" Value="#202943"/>
                                <Setter TargetName="Dot"  Property="Background" Value="#8B7FC7"/>
                                <Setter Property="Foreground" Value="#E8E7ED"/>
                            </Trigger>
                        </ControlTemplate.Triggers>
                    </ControlTemplate>
                </Setter.Value>
            </Setter>
        </Style>

        <Style x:Key="IconBtn" TargetType="Button">
            <Setter Property="Background" Value="Transparent"/>
            <Setter Property="Foreground" Value="{StaticResource TextMuted}"/>
            <Setter Property="Width" Value="38"/>
            <Setter Property="Height" Value="32"/>
            <Setter Property="Cursor" Value="Hand"/>
            <Setter Property="FontSize" Value="12"/>
            <Setter Property="Template">
                <Setter.Value>
                    <ControlTemplate TargetType="Button">
                        <Border x:Name="Bd" Background="{TemplateBinding Background}" CornerRadius="6">
                            <ContentPresenter HorizontalAlignment="Center" VerticalAlignment="Center"/>
                        </Border>
                        <ControlTemplate.Triggers>
                            <Trigger Property="IsMouseOver" Value="True">
                                <Setter TargetName="Bd" Property="Background" Value="#338B7FC7"/>
                                <Setter Property="Foreground" Value="#8B7FC7"/>
                            </Trigger>
                        </ControlTemplate.Triggers>
                    </ControlTemplate>
                </Setter.Value>
            </Setter>
        </Style>

        <Style x:Key="ActBtn" TargetType="Button">
            <Setter Property="Background" Value="Transparent"/>
            <Setter Property="Foreground" Value="{StaticResource TextMuted}"/>
            <Setter Property="FontSize" Value="11"/>
            <Setter Property="Cursor" Value="Hand"/>
            <Setter Property="HorizontalAlignment" Value="Stretch"/>
            <Setter Property="Margin" Value="0,2"/>
            <Setter Property="Template">
                <Setter.Value>
                    <ControlTemplate TargetType="Button">
                        <Border x:Name="Bd" Background="{TemplateBinding Background}" CornerRadius="6" Padding="10,7">
                            <ContentPresenter HorizontalAlignment="Left" VerticalAlignment="Center"/>
                        </Border>
                        <ControlTemplate.Triggers>
                            <Trigger Property="IsMouseOver" Value="True">
                                <Setter TargetName="Bd" Property="Background" Value="#202943"/>
                                <Setter Property="Foreground" Value="#E8E7ED"/>
                            </Trigger>
                        </ControlTemplate.Triggers>
                    </ControlTemplate>
                </Setter.Value>
            </Setter>
        </Style>
    </Window.Resources>

    <Border x:Name="RootBorder" BorderBrush="#202943" BorderThickness="1" CornerRadius="12">
        <Border.Background>
            <LinearGradientBrush StartPoint="0,0" EndPoint="1,1">
                <GradientStop Color="#0B1020" Offset="0"/>
                <GradientStop Color="#0D1326" Offset="1"/>
            </LinearGradientBrush>
        </Border.Background>
        <Border.Effect>
            <DropShadowEffect Color="#000000" BlurRadius="24" ShadowDepth="0" Opacity="0.5"/>
        </Border.Effect>

        <Grid>
            <Grid.RowDefinitions>
                <RowDefinition Height="48"/>
                <RowDefinition Height="*"/>
                <RowDefinition Height="150"/>
            </Grid.RowDefinitions>

            <Border x:Name="TitleStrip" Grid.Row="0" Background="#151C30" CornerRadius="12,12,0,0">
                <Grid Margin="18,0,10,0">
                    <Grid.ColumnDefinitions>
                        <ColumnDefinition Width="Auto"/>
                        <ColumnDefinition Width="*"/>
                        <ColumnDefinition Width="Auto"/>
                    </Grid.ColumnDefinitions>
                    <StackPanel Orientation="Horizontal" VerticalAlignment="Center">
                        <Image x:Name="TitleIconImg" Width="22" Height="22" Stretch="Uniform" Visibility="Collapsed" VerticalAlignment="Center" Margin="0,0,8,0"/>
                        <TextBlock x:Name="TitleAsciiBunny" Text="(\(\ " FontFamily="Consolas" FontSize="14" FontWeight="Bold" Foreground="{StaticResource Accent}" VerticalAlignment="Center"/>
                        <TextBlock Text="BunnySSTool" FontSize="14" FontWeight="SemiBold" Foreground="{StaticResource TextMain}" VerticalAlignment="Center" Margin="2,0,0,0"/>
                        <TextBlock Text="思春期症候群" FontSize="10.5" Foreground="{StaticResource Highlight}" VerticalAlignment="Center" Margin="10,1,0,0"/>
                    </StackPanel>
                    <TextBlock Grid.Column="1" x:Name="InstPathTop" Text="" FontSize="9.5" Foreground="{StaticResource TextDim}"
                               VerticalAlignment="Center" TextAlignment="Center" TextTrimming="CharacterEllipsis"/>
                    <StackPanel Grid.Column="2" Orientation="Horizontal" VerticalAlignment="Center">
                        <Button x:Name="MinBtn"   Style="{StaticResource IconBtn}" Content="_"/>
                        <Button x:Name="CloseBtn" Style="{StaticResource IconBtn}" Content="X" Margin="4,0,0,0"/>
                    </StackPanel>
                </Grid>
            </Border>

            <Grid Grid.Row="1">
                <Grid.ColumnDefinitions>
                    <ColumnDefinition Width="200"/>
                    <ColumnDefinition Width="420"/>
                    <ColumnDefinition Width="*"/>
                </Grid.ColumnDefinitions>

                <Border Grid.Column="0" Background="#0D1326" BorderBrush="#202943" BorderThickness="0,0,1,0">
                    <Grid>
                        <Grid.RowDefinitions>
                            <RowDefinition Height="Auto"/>
                            <RowDefinition Height="Auto"/>
                            <RowDefinition Height="*"/>
                            <RowDefinition Height="Auto"/>
                        </Grid.RowDefinitions>

                        <StackPanel Grid.Row="0" Margin="14,16,14,12" HorizontalAlignment="Center">
                            <Image x:Name="BunnyImg" Width="160" Height="160" Stretch="Uniform" Visibility="Collapsed"/>
                            <Border x:Name="BunnyAsciiBox" Background="#0B1020" CornerRadius="10" Padding="8,10" Width="172">
                                <Border.BorderBrush><SolidColorBrush Color="#202943" Opacity="0.7"/></Border.BorderBrush>
                                <TextBlock x:Name="BunnyBlock" FontFamily="Consolas" FontSize="11"
                                           Foreground="{StaticResource Accent}" HorizontalAlignment="Center"
                                           TextAlignment="Center" xml:space="preserve"/>
                            </Border>
                        </StackPanel>

                        <TextBlock Grid.Row="1" Text="CATEGORIES" FontSize="9" FontWeight="Bold"
                                   Foreground="{StaticResource TextDim}" Margin="16,0,0,6"/>
                        <StackPanel Grid.Row="2" x:Name="CatRail" Margin="12,0,12,4"/>

                        <Border Grid.Row="3" BorderBrush="#202943" BorderThickness="0,1,0,0" Margin="0,8,0,10">
                            <StackPanel Margin="12,10,12,4">
                                <TextBlock Text="ACTIONS" FontSize="9" FontWeight="Bold" Foreground="{StaticResource TextDim}" Margin="4,0,0,6"/>
                                <Button x:Name="OpenFolderBtn" Content="Open Install Folder"    Style="{StaticResource ActBtn}"/>
                                <Button x:Name="ClearCacheBtn" Content="Clear Downloaded Files" Style="{StaticResource ActBtn}"/>
                                <Button x:Name="OpenCmdBtn"    Content="Open CMD"              Style="{StaticResource ActBtn}"/>
                                <TextBlock Text="kxzyyyy" FontSize="9.5" Foreground="{StaticResource TextDim}" Margin="4,8,0,0"/>
                            </StackPanel>
                        </Border>
                    </Grid>
                </Border>

                <Border Grid.Column="1" Background="#151C30" BorderBrush="#202943" BorderThickness="0,0,1,0">
                    <Grid>
                        <Grid.RowDefinitions>
                            <RowDefinition Height="Auto"/>
                            <RowDefinition Height="Auto"/>
                            <RowDefinition Height="*"/>
                        </Grid.RowDefinitions>

                        <Border Grid.Row="0" Background="#202943" CornerRadius="8" Margin="14,14,14,10" Padding="12,8">
                            <Grid>
                                <Grid.ColumnDefinitions>
                                    <ColumnDefinition Width="Auto"/>
                                    <ColumnDefinition Width="*"/>
                                </Grid.ColumnDefinitions>
                                <TextBlock Text="⌕" FontSize="16" Foreground="{StaticResource TextMuted}" VerticalAlignment="Center" Margin="0,0,8,0"/>
                                <TextBox Grid.Column="1" x:Name="SearchBox" Text="" Background="Transparent" BorderThickness="0"
                                         Foreground="{StaticResource TextMain}" FontSize="12" CaretBrush="{StaticResource Accent}"
                                         VerticalContentAlignment="Center"/>
                            </Grid>
                        </Border>

                        <TextBlock Grid.Row="1" x:Name="ListHeader" Text="ALL TOOLS" FontSize="9" FontWeight="Bold"
                                   Foreground="{StaticResource TextDim}" Margin="18,0,0,6"/>

                        <ScrollViewer Grid.Row="2" x:Name="ListScroll" VerticalScrollBarVisibility="Auto" HorizontalScrollBarVisibility="Disabled">
                            <StackPanel x:Name="ToolListPanel" Margin="10,0,10,12"/>
                        </ScrollViewer>
                    </Grid>
                </Border>

                <Border Grid.Column="2" Background="#0D1326">
                    <Grid>
                        <Grid.RowDefinitions>
                            <RowDefinition Height="*"/>
                            <RowDefinition Height="Auto"/>
                        </Grid.RowDefinitions>

                        <Grid Grid.Row="0" Margin="28,24,28,16">
                            <Grid.RowDefinitions>
                                <RowDefinition Height="Auto"/>
                                <RowDefinition Height="Auto"/>
                                <RowDefinition Height="Auto"/>
                                <RowDefinition Height="*"/>
                            </Grid.RowDefinitions>

                            <StackPanel x:Name="EmptyState" Grid.RowSpan="4" HorizontalAlignment="Center" VerticalAlignment="Center">
                                <Image x:Name="HeroBunnyImg" Width="220" Height="220" Stretch="Uniform" Visibility="Collapsed"/>
                                <Border x:Name="HeroBunnyBox" Background="#0B1020" CornerRadius="14" Padding="14,16" Width="240" Margin="0,0,0,18">
                                    <Border.BorderBrush><SolidColorBrush Color="#202943" Opacity="0.7"/></Border.BorderBrush>
                                    <TextBlock x:Name="HeroBunnyBlock" FontFamily="Consolas" FontSize="14"
                                               Foreground="{StaticResource Accent}" HorizontalAlignment="Center"
                                               TextAlignment="Center" xml:space="preserve"/>
                                </Border>
                                <TextBlock Text="Select a tool" FontSize="18" FontWeight="SemiBold" Foreground="{StaticResource TextMain}" HorizontalAlignment="Center"/>
                                <TextBlock Text="Pick something from the list to inspect it here." FontSize="11.5"
                                           Foreground="{StaticResource TextMuted}" HorizontalAlignment="Center" Margin="0,6,0,0"/>
                            </StackPanel>

                            <StackPanel x:Name="DetailPanel" Grid.RowSpan="4" Visibility="Collapsed">
                                <Border Grid.Row="0" x:Name="TypeBadgeHost" Background="#8B7FC7" CornerRadius="10" Padding="14,5" HorizontalAlignment="Left" Margin="0,0,0,16">
                                    <TextBlock x:Name="TypeBadge" Text="GITHUB" FontSize="10.5" FontWeight="Bold" Foreground="White"/>
                                </Border>
                                <TextBlock Grid.Row="1" x:Name="DetailName" Text="" FontSize="30" FontWeight="Bold" Foreground="{StaticResource TextMain}" TextWrapping="Wrap" Margin="0,0,0,8"/>
                                <TextBlock Grid.Row="2" x:Name="DetailCat" Text="" FontSize="11" Foreground="{StaticResource Highlight}" Margin="0,0,0,18"/>
                                <Border Grid.Row="3" Background="#202943" CornerRadius="10" Padding="18,14">
                                    <Border.BorderBrush><SolidColorBrush Color="#2A3450" Opacity="0.8"/></Border.BorderBrush>
                                    <TextBlock x:Name="DetailDesc" Text="" FontSize="13" Foreground="#E8E7ED" TextWrapping="Wrap" LineHeight="22"/>
                                </Border>
                            </StackPanel>
                        </Grid>

                        <Border Grid.Row="1" Margin="28,0,28,24">
                            <Button x:Name="LaunchBtn" Height="56" IsEnabled="False" Cursor="Hand">
                                <Button.Template>
                                    <ControlTemplate TargetType="Button">
                                        <Grid>
                                            <Border x:Name="LbGlow" CornerRadius="14" Background="#8B7FC7" Opacity="0" Margin="-4"/>
                                            <Border x:Name="LbBg" CornerRadius="12" BorderThickness="1.5">
                                                <Border.Background>
                                                    <LinearGradientBrush StartPoint="0,0" EndPoint="1,0">
                                                        <GradientStop x:Name="Gs1" Color="#8B7FC7" Offset="0"/>
                                                        <GradientStop x:Name="Gs2" Color="#D98FA8" Offset="1"/>
                                                    </LinearGradientBrush>
                                                </Border.Background>
                                                <Border.BorderBrush><SolidColorBrush Color="#BFC7E8" Opacity="0.4"/></Border.BorderBrush>
                                                <TextBlock x:Name="LbText" Text="LAUNCH" FontSize="15" FontWeight="Bold"
                                                           Foreground="#0B1020" HorizontalAlignment="Center" VerticalAlignment="Center"/>
                                            </Border>
                                        </Grid>
                                        <ControlTemplate.Triggers>
                                            <Trigger Property="IsEnabled" Value="False">
                                                <Setter TargetName="LbBg" Property="Opacity" Value="0.3"/>
                                                <Setter TargetName="LbText" Property="Text" Value="SELECT A TOOL"/>
                                            </Trigger>
                                            <MultiTrigger>
                                                <MultiTrigger.Conditions>
                                                    <Condition Property="IsMouseOver" Value="True"/>
                                                    <Condition Property="IsEnabled" Value="True"/>
                                                </MultiTrigger.Conditions>
                                                <Setter TargetName="LbGlow" Property="Opacity" Value="0.45"/>
                                            </MultiTrigger>
                                        </ControlTemplate.Triggers>
                                    </ControlTemplate>
                                </Button.Template>
                            </Button>
                        </Border>
                    </Grid>
                </Border>
            </Grid>

            <Border Grid.Row="2" Background="#080D1A" BorderBrush="#202943" BorderThickness="0,1,0,0" CornerRadius="0,0,12,12">
                <Grid Margin="18,12,18,12">
                    <Grid.ColumnDefinitions>
                        <ColumnDefinition Width="200"/>
                        <ColumnDefinition Width="*"/>
                    </Grid.ColumnDefinitions>

                    <StackPanel Grid.Column="0" Orientation="Horizontal" VerticalAlignment="Top">
                        <Ellipse x:Name="StatusOrb" Width="14" Height="14" Fill="#8B7FC7" VerticalAlignment="Center" Margin="0,2,12,0">
                            <Ellipse.Effect>
                                <DropShadowEffect x:Name="OrbGlow" Color="#8B7FC7" BlurRadius="14" ShadowDepth="0" Opacity="0.8"/>
                            </Ellipse.Effect>
                        </Ellipse>
                        <StackPanel>
                            <TextBlock x:Name="StatusTitle" Text="Ready" FontSize="14" FontWeight="SemiBold" Foreground="{StaticResource TextMain}"/>
                            <TextBlock x:Name="StatusSub" Text="Pick a tool to launch or download it." FontSize="10" Foreground="{StaticResource TextMuted}" TextWrapping="Wrap" MaxWidth="170"/>
                        </StackPanel>
                    </StackPanel>

                    <Border Grid.Column="1" Background="#0B1020" CornerRadius="8" Padding="14,10" Margin="14,0,0,0">
                        <Border.BorderBrush><SolidColorBrush Color="#202943" Opacity="0.7"/></Border.BorderBrush>
                        <Grid>
                            <Grid.RowDefinitions>
                                <RowDefinition Height="Auto"/>
                                <RowDefinition Height="*"/>
                            </Grid.RowDefinitions>
                            <TextBlock Text="ACTIVITY LOG" FontSize="9" FontWeight="Bold" Foreground="#5A6080" FontFamily="Consolas" Margin="0,0,0,4"/>
                            <TextBox Grid.Row="1" x:Name="LogBox" Background="Transparent" Foreground="#BFC7E8"
                                     BorderThickness="0" FontFamily="Consolas" FontSize="11" IsReadOnly="True"
                                     VerticalScrollBarVisibility="Auto" TextWrapping="Wrap"/>
                        </Grid>
                    </Border>
                </Grid>
            </Border>
        </Grid>
    </Border>
</Window>
"@

$reader = New-Object System.Xml.XmlNodeReader $xaml
$window = [Windows.Markup.XamlReader]::Load($reader)

$MinBtn        = $window.FindName("MinBtn")
$CloseBtn      = $window.FindName("CloseBtn")
$TitleIconImg  = $window.FindName("TitleIconImg")
$TitleAsciiBunny = $window.FindName("TitleAsciiBunny")
$StatusTitle   = $window.FindName("StatusTitle")
$StatusSub     = $window.FindName("StatusSub")
$StatusOrb     = $window.FindName("StatusOrb")
$OrbGlow       = $window.FindName("OrbGlow")
$LogBox        = $window.FindName("LogBox")
$CatRail       = $window.FindName("CatRail")
$ToolListPanel = $window.FindName("ToolListPanel")
$ListHeader    = $window.FindName("ListHeader")
$SearchBox     = $window.FindName("SearchBox")
$OpenFolderBtn = $window.FindName("OpenFolderBtn")
$ClearCacheBtn = $window.FindName("ClearCacheBtn")
$OpenCmdBtn    = $window.FindName("OpenCmdBtn")
$BunnyBlock    = $window.FindName("BunnyBlock")
$BunnyImg      = $window.FindName("BunnyImg")
$BunnyAsciiBox = $window.FindName("BunnyAsciiBox")
$HeroBunnyBlock= $window.FindName("HeroBunnyBlock")
$HeroBunnyImg  = $window.FindName("HeroBunnyImg")
$HeroBunnyBox  = $window.FindName("HeroBunnyBox")
$InstPathTop   = $window.FindName("InstPathTop")
$RootBorder    = $window.FindName("RootBorder")
$TitleStrip    = $window.FindName("TitleStrip")
$EmptyState    = $window.FindName("EmptyState")
$DetailPanel   = $window.FindName("DetailPanel")
$TypeBadge     = $window.FindName("TypeBadge")
$TypeBadgeHost = $window.FindName("TypeBadgeHost")
$DetailName    = $window.FindName("DetailName")
$DetailCat     = $window.FindName("DetailCat")
$DetailDesc    = $window.FindName("DetailDesc")
$LaunchBtn     = $window.FindName("LaunchBtn")

$InstPathTop.Text = "Downloads saved to  $env:USERPROFILE\Downloads\BunnySSTool".Replace('$env:USERPROFILE',$env:USERPROFILE)

$bgImg = Get-AssetPath "bg.png"
if ($bgImg) {
    $b = New-ImageBrush $bgImg 0.08
    if ($b) { $RootBorder.Background = $b }
}
$headerImg = Get-AssetPath "header.png"
if ($headerImg) {
    $b = New-ImageBrush $headerImg 0.45
    if ($b) { $TitleStrip.Background = $b }
}
$bunnyImgPath = Get-AssetPath "bunny.png"
if ($bunnyImgPath) {
    $bmp = New-BitmapImage $bunnyImgPath
    if ($bmp) {
        $BunnyImg.Source = $bmp
        $BunnyImg.Visibility = [System.Windows.Visibility]::Visible
        $BunnyAsciiBox.Visibility = [System.Windows.Visibility]::Collapsed
        $HeroBunnyImg.Source = $bmp
        $HeroBunnyImg.Visibility = [System.Windows.Visibility]::Visible
        $HeroBunnyBox.Visibility = [System.Windows.Visibility]::Collapsed
    }
}

$hairclipPath = Get-AssetPath "BunnnyHairclipFavicon.png"
if ($hairclipPath) {
    try {
        $iconBmp = New-BitmapImage $hairclipPath
        if ($iconBmp) {
            $TitleIconImg.Source = $iconBmp
            $TitleIconImg.Visibility = [System.Windows.Visibility]::Visible
            $TitleAsciiBunny.Visibility = [System.Windows.Visibility]::Collapsed
        }
    } catch {}
}

$script:SelectedTool   = $null
$script:ActiveCategory = "All"
$script:RowButtons     = @()

function Write-Log {
    param([string]$msg)
    $time = Get-Date -Format "HH:mm:ss"
    $LogBox.Dispatcher.Invoke([Action]{
        $LogBox.AppendText("[$time] $msg`r`n")
        $LogBox.ScrollToEnd()
    })
}

function Set-Status {
    param($title, $sub, [string]$orbColor = "#8B7FC7")
    $window.Dispatcher.Invoke([Action]{
        $StatusTitle.Text = $title
        $StatusSub.Text   = $sub
        $c = [Windows.Media.ColorConverter]::ConvertFromString($orbColor)
        $orbBrush = [Windows.Media.SolidColorBrush]::new($c)
        $orbBrush.Freeze()
        $StatusOrb.Fill = $orbBrush
        $OrbGlow.Color = $c
    })
}

function Invoke-LaunchTool {
    param($tool)
    $tn = $tool.Name
    $td = $tool

    switch ($td.Type) {
        "Link" {
            Start-Process $td.URL
            Write-Log "Opened $tn in browser."
            Set-Status "Ready" "Opened $tn in browser." "#8B7FC7"
        }
        "Powershell" {
            Set-Status "Running" "Launching $tn..." "#8B7FC7"
            Write-Log "Starting: $tn"
            $tempScript = [System.IO.Path]::Combine($env:TEMP, "bunny_$([guid]::NewGuid().ToString('N')).ps1")
            Set-Content -LiteralPath $tempScript -Value $td.Command -Encoding UTF8 -Force
            $startArgs = '/c start "BunnySSTool" powershell.exe -NoExit -NoProfile -ExecutionPolicy Bypass -File "' + $tempScript + '"'
            Start-Process -FilePath "cmd.exe" -ArgumentList $startArgs -WindowStyle Hidden
            Write-Log "Launched: $tn"
            Set-Status "Ready" "$tn launched." "#8B7FC7"
        }
        "EXE" {
            Set-Status "Downloading" "Fetching $tn..." "#8B7FC7"
            Write-Log "Starting download: $tn"
            $rs = [runspacefactory]::CreateRunspace()
            $rs.ApartmentState = "STA"; $rs.ThreadOptions = "ReuseThread"; $rs.Open()
            $rs.SessionStateProxy.SetVariable("tData", $td)
            $rs.SessionStateProxy.SetVariable("installDir", $script:InstallDir)
            $rs.SessionStateProxy.SetVariable("dispatcher", $window.Dispatcher)
            $rs.SessionStateProxy.SetVariable("StatusTitle", $StatusTitle)
            $rs.SessionStateProxy.SetVariable("StatusSub",   $StatusSub)
            $rs.SessionStateProxy.SetVariable("StatusOrb",   $StatusOrb)
            $rs.SessionStateProxy.SetVariable("OrbGlow",     $OrbGlow)
            $rs.SessionStateProxy.SetVariable("LogBox",      $LogBox)
            $rs.SessionStateProxy.SetVariable("launchBtn",   $LaunchBtn)
            $ps = [powershell]::Create(); $ps.Runspace = $rs
            $null = $ps.AddScript({
                function Set-StatusBg { param($title,$sub,$orbColor)
                    $dispatcher.Invoke([Action]{
                        $StatusTitle.Text=$title; $StatusSub.Text=$sub
                        $c = [Windows.Media.ColorConverter]::ConvertFromString($orbColor)
                        $brush = [Windows.Media.SolidColorBrush]::new($c); $brush.Freeze()
                        $StatusOrb.Fill = $brush; $OrbGlow.Color = $c
                    })
                }
                function Write-LogBg { param($msg)
                    $dispatcher.Invoke([Action]{ $LogBox.AppendText("[$(Get-Date -f 'HH:mm:ss')] $msg`n"); $LogBox.ScrollToEnd() })
                }
                try {
                    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
                    $name = $tData.Name; $url = $tData.URL; $cat = $tData.Category
                    $destDir = "$installDir\$cat\$name"
                    if (-not (Test-Path $destDir)) { New-Item -ItemType Directory -Path $destDir -Force | Out-Null }

                    if ($url -match "github\.com/([^/]+)/([^/]+)/releases/latest$") {
                        $owner = $Matches[1]; $repo = $Matches[2]
                        $apiUrl = "https://api.github.com/repos/$owner/$repo/releases/latest"
                        $release = Invoke-RestMethod -Uri $apiUrl -Headers @{ "User-Agent" = "BunnySSTool" } -ErrorAction Stop
                        $asset = $release.assets | Where-Object { $_.name -match "\.(zip|exe)$" } | Select-Object -First 1
                        if (-not $asset) { throw "No downloadable asset found." }
                        $dlUrl = $asset.browser_download_url; $fileName = $asset.name
                    } else {
                        $dlUrl = $url; $fileName = ($url -split "/")[-1]
                    }

                    $destFile = "$destDir\$fileName"
                    if (Test-Path $destFile) { Write-LogBg "Cached: $fileName - skipping download." }
                    else {
                        Write-LogBg "Downloading $fileName..."
                        $wc = New-Object System.Net.WebClient; $wc.Headers.Add("User-Agent","BunnySSTool")
                        $wc.DownloadFile($dlUrl, $destFile)
                        Write-LogBg "Download complete: $fileName"
                    }
                    if ($fileName -match "\.zip$") {
                        Write-LogBg "Extracting..."
                        Expand-Archive -Path $destFile -DestinationPath $destDir -Force -ErrorAction Stop
                        $exe = Get-ChildItem -Path $destDir -Filter "*.exe" -Recurse | Select-Object -First 1
                        if ($exe) { Write-LogBg "Launching $($exe.Name)..."; Start-Process -FilePath $exe.FullName }
                        else { $dispatcher.Invoke([Action]{ Start-Process -FilePath explorer.exe -ArgumentList "`"$destDir`"" }) }
                    } else {
                        Write-LogBg "Launching $fileName..."
                        Start-Process -FilePath $destFile
                    }
                    Set-StatusBg "Ready" "$name launched successfully." "#8B7FC7"
                } catch {
                    Write-LogBg "Error: $_"
                    Set-StatusBg "Error" "Something went wrong with $($tData.Name)." "#C78F8F"
                }
                $dispatcher.Invoke([Action]{ $launchBtn.IsEnabled = $true })
                $rs.Close()
            })
            $null = $ps.BeginInvoke()
            return
        }
    }
    $LaunchBtn.IsEnabled = $true
}

foreach ($cat in $Categories) {
    $rb = New-Object System.Windows.Controls.RadioButton
    $rb.Style = $window.Resources["CatPill"]
    $rb.GroupName = "Cat"
    $rb.Content = if ($cat -eq "All") { "All Tools" } else { $cat }
    $rb.Tag = $cat
    $rb.Add_Checked({
        $script:ActiveCategory = $_.Source.Tag
        Update-ToolList
    })
    $CatRail.Children.Add($rb) | Out-Null
}

function Update-ToolList {
    $script:RowButtons = @()
    $ToolListPanel.Children.Clear()
    $query = $SearchBox.Text.Trim().ToLowerInvariant()
    $hasQuery = $query.Length -gt 0

    $tools = if ($script:ActiveCategory -eq "All") {
        $ToolData
    } else {
        $ToolData | Where-Object { $_.Category -eq $script:ActiveCategory }
    }
    if ($hasQuery) {
        $tools = $tools | Where-Object {
            $_.Name.ToLowerInvariant().Contains($query) -or
            $_.Desc.ToLowerInvariant().Contains($query) -or
            $_.Category.ToLowerInvariant().Contains($query)
        }
    }

    $headerText = if ($hasQuery) { "RESULTS ($(@($tools).Count))" } else { ($script:ActiveCategory.ToUpper() + " ($(@($tools).Count))") }
    $ListHeader.Text = $headerText

    foreach ($tool in $tools) {
        $t = $tool

        $row = New-Object System.Windows.Controls.Button
        $row.HorizontalAlignment = [System.Windows.HorizontalAlignment]::Stretch
        $row.HorizontalContentAlignment = [System.Windows.HorizontalAlignment]::Stretch
        $row.Height = 58
        $row.Margin = "0,2"
        $row.Cursor = [System.Windows.Input.Cursors]::Hand
        $row.Tag = $t

        $rowBg = [Windows.Media.SolidColorBrush]::new([Windows.Media.Color]::FromRgb(0x15, 0x1C, 0x30))
        $rowBg.Freeze()

        $row.Template = [Windows.Markup.XamlReader]::Parse(
            "<ControlTemplate xmlns='http://schemas.microsoft.com/winfx/2006/xaml/presentation' xmlns:x='http://schemas.microsoft.com/winfx/2006/xaml' TargetType='Button'>" +
            "  <Border x:Name='RowBd' Background='{TemplateBinding Background}' CornerRadius='8' Padding='14,0'>" +
            "    <Grid>" +
            "      <Grid.ColumnDefinitions>" +
            "        <ColumnDefinition Width='3'/>" +
            "        <ColumnDefinition Width='10'/>" +
            "        <ColumnDefinition Width='*'/>" +
            "        <ColumnDefinition Width='Auto'/>" +
            "      </Grid.ColumnDefinitions>" +
            "      <Border x:Name='AccentBar' Grid.Column='0' Width='3' CornerRadius='2' Background='Transparent' VerticalAlignment='Stretch' Margin='0,8'/>" +
            "      <ContentPresenter Grid.Column='2' VerticalAlignment='Center'/>" +
            "      <TextBlock x:Name='Arrow' Grid.Column='3' Text='›' FontSize='18' Foreground='#5A6080' VerticalAlignment='Center' Margin='0,0,2,0'/>" +
            "    </Grid>" +
            "  </Border>" +
            "  <ControlTemplate.Triggers>" +
            "    <Trigger Property='IsMouseOver' Value='True'>" +
            "      <Setter TargetName='RowBd' Property='Background' Value='#202943'/>" +
            "      <Setter TargetName='Arrow' Property='Foreground' Value='#8B7FC7'/>" +
            "    </Trigger>" +
            "  </ControlTemplate.Triggers>" +
            "</ControlTemplate>"
        )
        $row.Background = $rowBg

        $content = New-Object System.Windows.Controls.StackPanel
        $nameRow = New-Object System.Windows.Controls.StackPanel
        $nameRow.Orientation = [System.Windows.Controls.Orientation]::Horizontal
        $nameBlock = New-Object System.Windows.Controls.TextBlock
        $nameBlock.Text = $t.Name
        $nameBlock.FontSize = 12.5
        $nameBlock.FontWeight = [System.Windows.FontWeights]::SemiBold
        $nameBlock.Foreground = [Windows.Media.BrushConverter]::new().ConvertFrom("#E8E7ED")
        $nameRow.Children.Add($nameBlock) | Out-Null

        $pill = New-Object System.Windows.Controls.Border
        $pill.Background = [Windows.Media.BrushConverter]::new().ConvertFrom("#8B7FC7")
        $pill.CornerRadius = [System.Windows.CornerRadius]::new(4)
        $pill.Padding = [System.Windows.Thickness]::new(7,1,7,1)
        $pill.Margin = [System.Windows.Thickness]::new(8,0,0,0)
        $pill.VerticalAlignment = [System.Windows.VerticalAlignment]::Center
        $pillText = New-Object System.Windows.Controls.TextBlock
        $pillText.Text = $t.Type.ToUpper()
        $pillText.FontSize = 8
        $pillText.FontWeight = [System.Windows.FontWeights]::Bold
        $pillText.Foreground = [Windows.Media.Brushes]::White
        $pill.Child = $pillText
        $nameRow.Children.Add($pill) | Out-Null

        $descBlock = New-Object System.Windows.Controls.TextBlock
        $descBlock.Text = $t.Desc
        $descBlock.FontSize = 10
        $descBlock.Foreground = [Windows.Media.BrushConverter]::new().ConvertFrom("#858BA3")
        $descBlock.TextTrimming = [System.Windows.TextTrimming]::CharacterEllipsis
        $descBlock.Margin = [System.Windows.Thickness]::new(0,2,0,0)

        $content.Children.Add($nameRow) | Out-Null
        $content.Children.Add($descBlock) | Out-Null
        $row.Content = $content

        $row.Add_Click({
            $b = $_.Source
            $tData = $b.Tag
            Select-Tool -Tool $tData -Row $b
        })

        $ToolListPanel.Children.Add($row) | Out-Null
        $script:RowButtons += $row
    }
}

($CatRail.Children | Where-Object { $_.Tag -eq "All" }).IsChecked = $true

function Select-Tool {
    param($Tool, $Row)

    foreach ($r in $script:RowButtons) {
        $bd = [Windows.Media.VisualTreeHelper]::GetChild($r, 0)
        if ($bd -and [Windows.Media.VisualTreeHelper]::GetChildrenCount($bd) -gt 0) {
            $grid = [Windows.Media.VisualTreeHelper]::GetChild($bd, 0)
            if ($grid -and [Windows.Media.VisualTreeHelper]::GetChildrenCount($grid) -gt 0) {
                $accentBar = [Windows.Media.VisualTreeHelper]::GetChild($grid, 0)
                if ($accentBar) { $accentBar.Background = [Windows.Media.Brushes]::Transparent }
            }
        }
        $r.Background = [Windows.Media.SolidColorBrush]::new([Windows.Media.Color]::FromRgb(0x15,0x1C,0x30))
    }

    $bd2 = [Windows.Media.VisualTreeHelper]::GetChild($Row, 0)
    if ($bd2 -and [Windows.Media.VisualTreeHelper]::GetChildrenCount($bd2) -gt 0) {
        $grid2 = [Windows.Media.VisualTreeHelper]::GetChild($bd2, 0)
        if ($grid2 -and [Windows.Media.VisualTreeHelper]::GetChildrenCount($grid2) -gt 0) {
            $accentBar2 = [Windows.Media.VisualTreeHelper]::GetChild($grid2, 0)
            if ($accentBar2) {
                $accentBar2.Background = [Windows.Media.BrushConverter]::new().ConvertFrom("#8B7FC7")
            }
        }
    }
    $selBg = [Windows.Media.SolidColorBrush]::new([Windows.Media.Color]::FromRgb(0x20,0x29,0x43))
    $selBg.Freeze()
    $Row.Background = $selBg

    $script:SelectedTool = $Tool

    $EmptyState.Visibility = [System.Windows.Visibility]::Collapsed
    $DetailPanel.Visibility = [System.Windows.Visibility]::Visible

    $TypeBadge.Text = $Tool.Type.ToUpper()
    $TypeBadgeHost.Background = [Windows.Media.BrushConverter]::new().ConvertFrom("#8B7FC7")

    $DetailName.Text = $Tool.Name
    $DetailCat.Text  = "Category  ·  " + $Tool.Category
    $DetailDesc.Text = $Tool.Desc

    $LaunchBtn.IsEnabled = $true
    Set-Status "Selected" "$($Tool.Name) ready to launch." "#8B7FC7"
}

$SearchBox.Add_TextChanged({ Update-ToolList })

$LaunchBtn.Add_Click({
    if (-not $script:SelectedTool) { return }
    $LaunchBtn.IsEnabled = $false
    Invoke-LaunchTool -tool $script:SelectedTool
})

$bunnyFrames = @(
    "  (\(\ `n (  -.-) `n  (__(`)`n   `` ``",
    "  (\(\ `n (  ^.^) `n  (__(`)`n   `` ``",
    "  (\(\ `n (  -.-) `n  (__(`)`n   `` ``",
    "  (\(\ `n (  -_-) `n  (__(`)`n   `` ``"
)
$heroBunnyFrames = @(
    "   (\(\   `n  (  -.-)  `n   (__(`)  `n    `` ``",
    "   (\(\   `n  (  ^.^)  `n   (__(`)  `n    `` ``",
    "   (\(\   `n  (  -.-)  `n   (__(`)  `n    `` ``",
    "   (\(\   `n  (  -_-)  `n   (__(`)  `n    `` ``"
)
$script:bunnyIdx = 0
$BunnyBlock.Text = $bunnyFrames[0]
$HeroBunnyBlock.Text = $heroBunnyFrames[0]
$bunnyTimer = New-Object System.Windows.Threading.DispatcherTimer
$bunnyTimer.Interval = [TimeSpan]::FromMilliseconds(900)
$bunnyTimer.Add_Tick({
    $script:bunnyIdx = ($script:bunnyIdx + 1) % $bunnyFrames.Count
    if ($BunnyImg.Visibility -ne [System.Windows.Visibility]::Visible) {
        $BunnyBlock.Text = $bunnyFrames[$script:bunnyIdx]
    }
    if ($HeroBunnyImg.Visibility -ne [System.Windows.Visibility]::Visible) {
        $HeroBunnyBlock.Text = $heroBunnyFrames[$script:bunnyIdx]
    }
})
$bunnyTimer.Start()

$window.Add_MouseLeftButtonDown({ try { $window.DragMove() } catch {} })
$CloseBtn.Add_Click({ $bunnyTimer.Stop(); $window.Close() })
$MinBtn.Add_Click({ $window.WindowState = "Minimized" })

$OpenFolderBtn.Add_Click({
    if (-not (Test-Path $script:InstallDir)) { New-Item -ItemType Directory -Path $script:InstallDir -Force | Out-Null }
    Start-Process explorer.exe $script:InstallDir
    Write-Log "Opened install folder."
})

$ClearCacheBtn.Add_Click({
    if (Test-Path $script:InstallDir) {
        $items = Get-ChildItem -Path $script:InstallDir -Force -ErrorAction SilentlyContinue
        $count = @($items).Count
        $items | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
        Write-Log "Cleared $count item(s) from install folder."
        Set-Status "Clean" "Removed downloaded files." "#8FC7A8"
    } else {
        Write-Log "Nothing to clear - install folder does not exist yet."
    }
})

$OpenCmdBtn.Add_Click({
    Start-Process -FilePath "cmd.exe"
    Write-Log "Opened CMD."
})

Write-Log "Files saved to: $script:InstallDir"
Set-Status "Ready" "Pick a tool to launch or download it." "#8B7FC7"

$window.ShowDialog() | Out-Null
