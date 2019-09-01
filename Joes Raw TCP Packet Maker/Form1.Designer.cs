namespace ZeroLengthWindow_Dos
{
    partial class Form1
    {
        /// <summary>
        /// Required designer variable.
        /// </summary>
        private System.ComponentModel.IContainer components = null;

        /// <summary>
        /// Clean up any resources being used.
        /// </summary>
        /// <param name="disposing">true if managed resources should be disposed; otherwise, false.</param>
        protected override void Dispose(bool disposing)
        {
            if (disposing && (components != null))
            {
                components.Dispose();
            }
            base.Dispose(disposing);
        }

        #region Windows Form Designer generated code

        /// <summary>
        /// Required method for Designer support - do not modify
        /// the contents of this method with the code editor.
        /// </summary>
        private void InitializeComponent()
        {
            System.ComponentModel.ComponentResourceManager resources = new System.ComponentModel.ComponentResourceManager(typeof(Form1));
            this.tbTarget = new System.Windows.Forms.TextBox();
            this.label1 = new System.Windows.Forms.Label();
            this.btnAttack = new System.Windows.Forms.Button();
            this.tbResults = new System.Windows.Forms.TextBox();
            this.label2 = new System.Windows.Forms.Label();
            this.cbAdapter = new System.Windows.Forms.ComboBox();
            this.label3 = new System.Windows.Forms.Label();
            this.pbr = new System.Windows.Forms.ProgressBar();
            this.bgw = new System.ComponentModel.BackgroundWorker();
            this.btnCancel = new System.Windows.Forms.Button();
            this.txtData = new System.Windows.Forms.TextBox();
            this.label4 = new System.Windows.Forms.Label();
            this.tbDestPort = new System.Windows.Forms.TextBox();
            this.label5 = new System.Windows.Forms.Label();
            this.label6 = new System.Windows.Forms.Label();
            this.tbSourceIP = new System.Windows.Forms.TextBox();
            this.label7 = new System.Windows.Forms.Label();
            this.tbSourcePort = new System.Windows.Forms.TextBox();
            this.gbFlags = new System.Windows.Forms.GroupBox();
            this.cbNone = new System.Windows.Forms.CheckBox();
            this.cbNs = new System.Windows.Forms.CheckBox();
            this.cbCwr = new System.Windows.Forms.CheckBox();
            this.cbEnc = new System.Windows.Forms.CheckBox();
            this.cbPsh = new System.Windows.Forms.CheckBox();
            this.cbRst = new System.Windows.Forms.CheckBox();
            this.cbUrg = new System.Windows.Forms.CheckBox();
            this.cbFin = new System.Windows.Forms.CheckBox();
            this.cbAck = new System.Windows.Forms.CheckBox();
            this.cbSyn = new System.Windows.Forms.CheckBox();
            this.tbSeqNo = new System.Windows.Forms.TextBox();
            this.tbAckNo = new System.Windows.Forms.TextBox();
            this.tbNumOfPackets = new System.Windows.Forms.TextBox();
            this.tbWinLen = new System.Windows.Forms.TextBox();
            this.tbSourceMac = new System.Windows.Forms.TextBox();
            this.tbDestMac = new System.Windows.Forms.TextBox();
            this.label8 = new System.Windows.Forms.Label();
            this.label9 = new System.Windows.Forms.Label();
            this.label10 = new System.Windows.Forms.Label();
            this.label11 = new System.Windows.Forms.Label();
            this.label12 = new System.Windows.Forms.Label();
            this.label13 = new System.Windows.Forms.Label();
            this.label14 = new System.Windows.Forms.Label();
            this.label15 = new System.Windows.Forms.Label();
            this.tbIdNo = new System.Windows.Forms.TextBox();
            this.tbTimeToLive = new System.Windows.Forms.TextBox();
            this.derp = new System.Windows.Forms.MenuStrip();
            this.helpToolStripMenuItem = new System.Windows.Forms.ToolStripMenuItem();
            this.srslyHELPToolStripMenuItem = new System.Windows.Forms.ToolStripMenuItem();
            this.aboutToolStripMenuItem = new System.Windows.Forms.ToolStripMenuItem();
            this.aboutMyAppToolStripMenuItem = new System.Windows.Forms.ToolStripMenuItem();
            this.visitSiteToolStripMenuItem = new System.Windows.Forms.ToolStripMenuItem();
            this.tbClearResults = new System.Windows.Forms.Button();
            this.gbFlags.SuspendLayout();
            this.derp.SuspendLayout();
            this.SuspendLayout();
            // 
            // tbTarget
            // 
            this.tbTarget.Location = new System.Drawing.Point(131, 83);
            this.tbTarget.Name = "tbTarget";
            this.tbTarget.Size = new System.Drawing.Size(199, 20);
            this.tbTarget.TabIndex = 0;
            // 
            // label1
            // 
            this.label1.AutoSize = true;
            this.label1.Font = new System.Drawing.Font("Microsoft Sans Serif", 8.25F, System.Drawing.FontStyle.Bold, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.label1.Location = new System.Drawing.Point(131, 67);
            this.label1.Name = "label1";
            this.label1.Size = new System.Drawing.Size(60, 13);
            this.label1.TabIndex = 1;
            this.label1.Text = "Target IP";
            // 
            // btnAttack
            // 
            this.btnAttack.Font = new System.Drawing.Font("Microsoft Sans Serif", 8.25F, System.Drawing.FontStyle.Bold, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.btnAttack.Location = new System.Drawing.Point(151, 463);
            this.btnAttack.Name = "btnAttack";
            this.btnAttack.Size = new System.Drawing.Size(116, 30);
            this.btnAttack.TabIndex = 2;
            this.btnAttack.Text = "Attack";
            this.btnAttack.UseVisualStyleBackColor = true;
            this.btnAttack.Click += new System.EventHandler(this.btnAttack_Click);
            // 
            // tbResults
            // 
            this.tbResults.Location = new System.Drawing.Point(8, 270);
            this.tbResults.Multiline = true;
            this.tbResults.Name = "tbResults";
            this.tbResults.ReadOnly = true;
            this.tbResults.ScrollBars = System.Windows.Forms.ScrollBars.Vertical;
            this.tbResults.Size = new System.Drawing.Size(547, 148);
            this.tbResults.TabIndex = 0;
            // 
            // label2
            // 
            this.label2.AutoSize = true;
            this.label2.Font = new System.Drawing.Font("Microsoft Sans Serif", 8.25F, System.Drawing.FontStyle.Bold, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.label2.Location = new System.Drawing.Point(12, 254);
            this.label2.Name = "label2";
            this.label2.Size = new System.Drawing.Size(53, 13);
            this.label2.TabIndex = 1;
            this.label2.Text = "Results:";
            // 
            // cbAdapter
            // 
            this.cbAdapter.FormattingEnabled = true;
            this.cbAdapter.Location = new System.Drawing.Point(15, 40);
            this.cbAdapter.Name = "cbAdapter";
            this.cbAdapter.Size = new System.Drawing.Size(544, 21);
            this.cbAdapter.TabIndex = 3;
            // 
            // label3
            // 
            this.label3.AutoSize = true;
            this.label3.Font = new System.Drawing.Font("Microsoft Sans Serif", 8.25F, System.Drawing.FontStyle.Bold, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.label3.Location = new System.Drawing.Point(11, 24);
            this.label3.Name = "label3";
            this.label3.Size = new System.Drawing.Size(91, 13);
            this.label3.TabIndex = 4;
            this.label3.Text = "Select Adapter";
            // 
            // pbr
            // 
            this.pbr.Location = new System.Drawing.Point(8, 424);
            this.pbr.Name = "pbr";
            this.pbr.Size = new System.Drawing.Size(547, 31);
            this.pbr.TabIndex = 5;
            // 
            // bgw
            // 
            this.bgw.WorkerReportsProgress = true;
            this.bgw.WorkerSupportsCancellation = true;
            this.bgw.DoWork += new System.ComponentModel.DoWorkEventHandler(this.bgw_DoWork);
            // 
            // btnCancel
            // 
            this.btnCancel.Font = new System.Drawing.Font("Microsoft Sans Serif", 8.25F, System.Drawing.FontStyle.Bold, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.btnCancel.Location = new System.Drawing.Point(296, 463);
            this.btnCancel.Name = "btnCancel";
            this.btnCancel.Size = new System.Drawing.Size(116, 30);
            this.btnCancel.TabIndex = 2;
            this.btnCancel.Text = "Cancel";
            this.btnCancel.UseVisualStyleBackColor = true;
            this.btnCancel.Click += new System.EventHandler(this.btnCancel_Click);
            // 
            // txtData
            // 
            this.txtData.Location = new System.Drawing.Point(134, 163);
            this.txtData.Multiline = true;
            this.txtData.Name = "txtData";
            this.txtData.ScrollBars = System.Windows.Forms.ScrollBars.Vertical;
            this.txtData.Size = new System.Drawing.Size(252, 101);
            this.txtData.TabIndex = 6;
            // 
            // label4
            // 
            this.label4.AutoSize = true;
            this.label4.Font = new System.Drawing.Font("Microsoft Sans Serif", 8.25F, System.Drawing.FontStyle.Bold, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.label4.Location = new System.Drawing.Point(131, 147);
            this.label4.Name = "label4";
            this.label4.Size = new System.Drawing.Size(107, 13);
            this.label4.TabIndex = 1;
            this.label4.Text = "Optional Payload:";
            // 
            // tbDestPort
            // 
            this.tbDestPort.Location = new System.Drawing.Point(334, 83);
            this.tbDestPort.Name = "tbDestPort";
            this.tbDestPort.Size = new System.Drawing.Size(52, 20);
            this.tbDestPort.TabIndex = 7;
            // 
            // label5
            // 
            this.label5.AutoSize = true;
            this.label5.Font = new System.Drawing.Font("Microsoft Sans Serif", 8.25F, System.Drawing.FontStyle.Bold, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.label5.Location = new System.Drawing.Point(335, 67);
            this.label5.Name = "label5";
            this.label5.Size = new System.Drawing.Size(46, 13);
            this.label5.TabIndex = 1;
            this.label5.Text = "Port #:";
            // 
            // label6
            // 
            this.label6.AutoSize = true;
            this.label6.Font = new System.Drawing.Font("Microsoft Sans Serif", 8.25F, System.Drawing.FontStyle.Bold, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.label6.Location = new System.Drawing.Point(131, 110);
            this.label6.Name = "label6";
            this.label6.Size = new System.Drawing.Size(63, 13);
            this.label6.TabIndex = 1;
            this.label6.Text = "Source IP";
            // 
            // tbSourceIP
            // 
            this.tbSourceIP.Location = new System.Drawing.Point(131, 124);
            this.tbSourceIP.Multiline = true;
            this.tbSourceIP.Name = "tbSourceIP";
            this.tbSourceIP.Size = new System.Drawing.Size(199, 20);
            this.tbSourceIP.TabIndex = 6;
            // 
            // label7
            // 
            this.label7.AutoSize = true;
            this.label7.Font = new System.Drawing.Font("Microsoft Sans Serif", 8.25F, System.Drawing.FontStyle.Bold, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.label7.Location = new System.Drawing.Point(335, 106);
            this.label7.Name = "label7";
            this.label7.Size = new System.Drawing.Size(46, 13);
            this.label7.TabIndex = 1;
            this.label7.Text = "Port #:";
            // 
            // tbSourcePort
            // 
            this.tbSourcePort.Location = new System.Drawing.Point(334, 124);
            this.tbSourcePort.Name = "tbSourcePort";
            this.tbSourcePort.Size = new System.Drawing.Size(52, 20);
            this.tbSourcePort.TabIndex = 7;
            // 
            // gbFlags
            // 
            this.gbFlags.Controls.Add(this.cbNone);
            this.gbFlags.Controls.Add(this.cbNs);
            this.gbFlags.Controls.Add(this.cbCwr);
            this.gbFlags.Controls.Add(this.cbEnc);
            this.gbFlags.Controls.Add(this.cbPsh);
            this.gbFlags.Controls.Add(this.cbRst);
            this.gbFlags.Controls.Add(this.cbUrg);
            this.gbFlags.Controls.Add(this.cbFin);
            this.gbFlags.Controls.Add(this.cbAck);
            this.gbFlags.Controls.Add(this.cbSyn);
            this.gbFlags.Font = new System.Drawing.Font("Microsoft Sans Serif", 8.25F, System.Drawing.FontStyle.Bold, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.gbFlags.Location = new System.Drawing.Point(8, 67);
            this.gbFlags.Name = "gbFlags";
            this.gbFlags.Size = new System.Drawing.Size(117, 174);
            this.gbFlags.TabIndex = 8;
            this.gbFlags.TabStop = false;
            this.gbFlags.Text = "Flags";
            // 
            // cbNone
            // 
            this.cbNone.AutoSize = true;
            this.cbNone.Font = new System.Drawing.Font("Microsoft Sans Serif", 8.25F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.cbNone.Location = new System.Drawing.Point(61, 151);
            this.cbNone.Name = "cbNone";
            this.cbNone.Size = new System.Drawing.Size(57, 17);
            this.cbNone.TabIndex = 0;
            this.cbNone.Text = "NONE";
            this.cbNone.UseVisualStyleBackColor = true;
            // 
            // cbNs
            // 
            this.cbNs.AutoSize = true;
            this.cbNs.Font = new System.Drawing.Font("Microsoft Sans Serif", 8.25F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.cbNs.Location = new System.Drawing.Point(7, 151);
            this.cbNs.Name = "cbNs";
            this.cbNs.Size = new System.Drawing.Size(41, 17);
            this.cbNs.TabIndex = 0;
            this.cbNs.Text = "NS";
            this.cbNs.UseVisualStyleBackColor = true;
            // 
            // cbCwr
            // 
            this.cbCwr.AutoSize = true;
            this.cbCwr.Font = new System.Drawing.Font("Microsoft Sans Serif", 8.25F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.cbCwr.Location = new System.Drawing.Point(7, 117);
            this.cbCwr.Name = "cbCwr";
            this.cbCwr.Size = new System.Drawing.Size(52, 17);
            this.cbCwr.TabIndex = 0;
            this.cbCwr.Text = "CWR";
            this.cbCwr.UseVisualStyleBackColor = true;
            // 
            // cbEnc
            // 
            this.cbEnc.AutoSize = true;
            this.cbEnc.Font = new System.Drawing.Font("Microsoft Sans Serif", 8.25F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.cbEnc.Location = new System.Drawing.Point(61, 117);
            this.cbEnc.Name = "cbEnc";
            this.cbEnc.Size = new System.Drawing.Size(48, 17);
            this.cbEnc.TabIndex = 0;
            this.cbEnc.Text = "ENC";
            this.cbEnc.UseVisualStyleBackColor = true;
            // 
            // cbPsh
            // 
            this.cbPsh.AutoSize = true;
            this.cbPsh.Font = new System.Drawing.Font("Microsoft Sans Serif", 8.25F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.cbPsh.Location = new System.Drawing.Point(61, 84);
            this.cbPsh.Name = "cbPsh";
            this.cbPsh.Size = new System.Drawing.Size(48, 17);
            this.cbPsh.TabIndex = 0;
            this.cbPsh.Text = "PSH";
            this.cbPsh.UseVisualStyleBackColor = true;
            // 
            // cbRst
            // 
            this.cbRst.AutoSize = true;
            this.cbRst.Font = new System.Drawing.Font("Microsoft Sans Serif", 8.25F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.cbRst.Location = new System.Drawing.Point(6, 84);
            this.cbRst.Name = "cbRst";
            this.cbRst.Size = new System.Drawing.Size(48, 17);
            this.cbRst.TabIndex = 0;
            this.cbRst.Text = "RST";
            this.cbRst.UseVisualStyleBackColor = true;
            // 
            // cbUrg
            // 
            this.cbUrg.AutoSize = true;
            this.cbUrg.Font = new System.Drawing.Font("Microsoft Sans Serif", 8.25F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.cbUrg.Location = new System.Drawing.Point(61, 53);
            this.cbUrg.Name = "cbUrg";
            this.cbUrg.Size = new System.Drawing.Size(50, 17);
            this.cbUrg.TabIndex = 0;
            this.cbUrg.Text = "URG";
            this.cbUrg.UseVisualStyleBackColor = true;
            // 
            // cbFin
            // 
            this.cbFin.AutoSize = true;
            this.cbFin.Font = new System.Drawing.Font("Microsoft Sans Serif", 8.25F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.cbFin.Location = new System.Drawing.Point(7, 53);
            this.cbFin.Name = "cbFin";
            this.cbFin.Size = new System.Drawing.Size(43, 17);
            this.cbFin.TabIndex = 0;
            this.cbFin.Text = "FIN";
            this.cbFin.UseVisualStyleBackColor = true;
            // 
            // cbAck
            // 
            this.cbAck.AutoSize = true;
            this.cbAck.Font = new System.Drawing.Font("Microsoft Sans Serif", 8.25F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.cbAck.Location = new System.Drawing.Point(61, 24);
            this.cbAck.Name = "cbAck";
            this.cbAck.Size = new System.Drawing.Size(47, 17);
            this.cbAck.TabIndex = 0;
            this.cbAck.Text = "ACK";
            this.cbAck.UseVisualStyleBackColor = true;
            this.cbAck.CheckedChanged += new System.EventHandler(this.cbAck_CheckedChanged);
            // 
            // cbSyn
            // 
            this.cbSyn.AutoSize = true;
            this.cbSyn.Font = new System.Drawing.Font("Microsoft Sans Serif", 8.25F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.cbSyn.Location = new System.Drawing.Point(7, 24);
            this.cbSyn.Name = "cbSyn";
            this.cbSyn.Size = new System.Drawing.Size(48, 17);
            this.cbSyn.TabIndex = 0;
            this.cbSyn.Text = "SYN";
            this.cbSyn.UseVisualStyleBackColor = true;
            // 
            // tbSeqNo
            // 
            this.tbSeqNo.Location = new System.Drawing.Point(397, 163);
            this.tbSeqNo.Name = "tbSeqNo";
            this.tbSeqNo.Size = new System.Drawing.Size(74, 20);
            this.tbSeqNo.TabIndex = 9;
            this.tbSeqNo.Text = "124";
            // 
            // tbAckNo
            // 
            this.tbAckNo.Enabled = false;
            this.tbAckNo.Location = new System.Drawing.Point(397, 205);
            this.tbAckNo.Name = "tbAckNo";
            this.tbAckNo.Size = new System.Drawing.Size(74, 20);
            this.tbAckNo.TabIndex = 9;
            this.tbAckNo.Text = "0";
            // 
            // tbNumOfPackets
            // 
            this.tbNumOfPackets.Location = new System.Drawing.Point(475, 205);
            this.tbNumOfPackets.Name = "tbNumOfPackets";
            this.tbNumOfPackets.Size = new System.Drawing.Size(79, 20);
            this.tbNumOfPackets.TabIndex = 9;
            this.tbNumOfPackets.Text = "99";
            // 
            // tbWinLen
            // 
            this.tbWinLen.Location = new System.Drawing.Point(475, 244);
            this.tbWinLen.Name = "tbWinLen";
            this.tbWinLen.Size = new System.Drawing.Size(79, 20);
            this.tbWinLen.TabIndex = 9;
            this.tbWinLen.Text = "0";
            // 
            // tbSourceMac
            // 
            this.tbSourceMac.Font = new System.Drawing.Font("Microsoft Sans Serif", 8.25F, System.Drawing.FontStyle.Bold, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.tbSourceMac.Location = new System.Drawing.Point(397, 83);
            this.tbSourceMac.Name = "tbSourceMac";
            this.tbSourceMac.Size = new System.Drawing.Size(158, 20);
            this.tbSourceMac.TabIndex = 9;
            this.tbSourceMac.Text = "B8:AC:6F:3C:9C:93";
            // 
            // tbDestMac
            // 
            this.tbDestMac.Font = new System.Drawing.Font("Microsoft Sans Serif", 8.25F, System.Drawing.FontStyle.Bold, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.tbDestMac.Location = new System.Drawing.Point(394, 126);
            this.tbDestMac.Name = "tbDestMac";
            this.tbDestMac.Size = new System.Drawing.Size(161, 20);
            this.tbDestMac.TabIndex = 9;
            this.tbDestMac.Text = "FF:FF:FF:FF:FF:FF";
            // 
            // label8
            // 
            this.label8.AutoSize = true;
            this.label8.Font = new System.Drawing.Font("Microsoft Sans Serif", 8.25F, System.Drawing.FontStyle.Bold, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.label8.Location = new System.Drawing.Point(391, 147);
            this.label8.Name = "label8";
            this.label8.Size = new System.Drawing.Size(76, 13);
            this.label8.TabIndex = 1;
            this.label8.Text = "Seq Number";
            // 
            // label9
            // 
            this.label9.AutoSize = true;
            this.label9.Font = new System.Drawing.Font("Microsoft Sans Serif", 8.25F, System.Drawing.FontStyle.Bold, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.label9.Location = new System.Drawing.Point(394, 186);
            this.label9.Name = "label9";
            this.label9.Size = new System.Drawing.Size(76, 13);
            this.label9.TabIndex = 1;
            this.label9.Text = "Ack Number";
            // 
            // label10
            // 
            this.label10.AutoSize = true;
            this.label10.Font = new System.Drawing.Font("Microsoft Sans Serif", 8.25F, System.Drawing.FontStyle.Bold, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.label10.Location = new System.Drawing.Point(476, 186);
            this.label10.Name = "label10";
            this.label10.Size = new System.Drawing.Size(82, 13);
            this.label10.TabIndex = 1;
            this.label10.Text = "# Of Packets";
            // 
            // label11
            // 
            this.label11.AutoSize = true;
            this.label11.Font = new System.Drawing.Font("Microsoft Sans Serif", 8.25F, System.Drawing.FontStyle.Bold, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.label11.Location = new System.Drawing.Point(476, 228);
            this.label11.Name = "label11";
            this.label11.Size = new System.Drawing.Size(72, 13);
            this.label11.TabIndex = 1;
            this.label11.Text = "Win Length";
            // 
            // label12
            // 
            this.label12.AutoSize = true;
            this.label12.Font = new System.Drawing.Font("Microsoft Sans Serif", 8.25F, System.Drawing.FontStyle.Bold, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.label12.Location = new System.Drawing.Point(394, 67);
            this.label12.Name = "label12";
            this.label12.Size = new System.Drawing.Size(151, 13);
            this.label12.TabIndex = 1;
            this.label12.Text = "Source HW MAC Address";
            // 
            // label13
            // 
            this.label13.AutoSize = true;
            this.label13.Font = new System.Drawing.Font("Microsoft Sans Serif", 8.25F, System.Drawing.FontStyle.Bold, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.label13.Location = new System.Drawing.Point(391, 110);
            this.label13.Name = "label13";
            this.label13.Size = new System.Drawing.Size(137, 13);
            this.label13.TabIndex = 1;
            this.label13.Text = "Dest HW MAC Address";
            // 
            // label14
            // 
            this.label14.AutoSize = true;
            this.label14.Font = new System.Drawing.Font("Microsoft Sans Serif", 8.25F, System.Drawing.FontStyle.Bold, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.label14.Location = new System.Drawing.Point(394, 228);
            this.label14.Name = "label14";
            this.label14.Size = new System.Drawing.Size(67, 13);
            this.label14.TabIndex = 1;
            this.label14.Text = "ID Number";
            // 
            // label15
            // 
            this.label15.AutoSize = true;
            this.label15.Font = new System.Drawing.Font("Microsoft Sans Serif", 8.25F, System.Drawing.FontStyle.Bold, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.label15.Location = new System.Drawing.Point(473, 147);
            this.label15.Name = "label15";
            this.label15.Size = new System.Drawing.Size(81, 13);
            this.label15.TabIndex = 1;
            this.label15.Text = "Time To Live";
            // 
            // tbIdNo
            // 
            this.tbIdNo.Location = new System.Drawing.Point(397, 244);
            this.tbIdNo.Name = "tbIdNo";
            this.tbIdNo.Size = new System.Drawing.Size(74, 20);
            this.tbIdNo.TabIndex = 9;
            this.tbIdNo.Text = "100";
            // 
            // tbTimeToLive
            // 
            this.tbTimeToLive.Location = new System.Drawing.Point(475, 163);
            this.tbTimeToLive.Name = "tbTimeToLive";
            this.tbTimeToLive.Size = new System.Drawing.Size(80, 20);
            this.tbTimeToLive.TabIndex = 9;
            this.tbTimeToLive.Text = "100";
            // 
            // derp
            // 
            this.derp.ImageScalingSize = new System.Drawing.Size(20, 20);
            this.derp.Items.AddRange(new System.Windows.Forms.ToolStripItem[] {
            this.helpToolStripMenuItem,
            this.aboutToolStripMenuItem});
            this.derp.Location = new System.Drawing.Point(0, 0);
            this.derp.Name = "derp";
            this.derp.Size = new System.Drawing.Size(562, 24);
            this.derp.TabIndex = 10;
            this.derp.Text = "menuStrip1";
            // 
            // helpToolStripMenuItem
            // 
            this.helpToolStripMenuItem.DropDownItems.AddRange(new System.Windows.Forms.ToolStripItem[] {
            this.srslyHELPToolStripMenuItem});
            this.helpToolStripMenuItem.Name = "helpToolStripMenuItem";
            this.helpToolStripMenuItem.Size = new System.Drawing.Size(44, 20);
            this.helpToolStripMenuItem.Text = "&Help";
            // 
            // srslyHELPToolStripMenuItem
            // 
            this.srslyHELPToolStripMenuItem.Name = "srslyHELPToolStripMenuItem";
            this.srslyHELPToolStripMenuItem.Size = new System.Drawing.Size(152, 22);
            this.srslyHELPToolStripMenuItem.Text = "Srsly, HELP!";
            this.srslyHELPToolStripMenuItem.Click += new System.EventHandler(this.srslyHELPToolStripMenuItem_Click);
            // 
            // aboutToolStripMenuItem
            // 
            this.aboutToolStripMenuItem.DropDownItems.AddRange(new System.Windows.Forms.ToolStripItem[] {
            this.aboutMyAppToolStripMenuItem,
            this.visitSiteToolStripMenuItem});
            this.aboutToolStripMenuItem.Name = "aboutToolStripMenuItem";
            this.aboutToolStripMenuItem.Size = new System.Drawing.Size(52, 20);
            this.aboutToolStripMenuItem.Text = "About";
            // 
            // aboutMyAppToolStripMenuItem
            // 
            this.aboutMyAppToolStripMenuItem.Name = "aboutMyAppToolStripMenuItem";
            this.aboutMyAppToolStripMenuItem.Size = new System.Drawing.Size(152, 22);
            this.aboutMyAppToolStripMenuItem.Text = "About My App";
            this.aboutMyAppToolStripMenuItem.Click += new System.EventHandler(this.aboutMyAppToolStripMenuItem_Click);
            // 
            // visitSiteToolStripMenuItem
            // 
            this.visitSiteToolStripMenuItem.Name = "visitSiteToolStripMenuItem";
            this.visitSiteToolStripMenuItem.Size = new System.Drawing.Size(152, 22);
            this.visitSiteToolStripMenuItem.Text = "Visit Site";
            this.visitSiteToolStripMenuItem.Click += new System.EventHandler(this.visitSiteToolStripMenuItem_Click);
            // 
            // tbClearResults
            // 
            this.tbClearResults.Font = new System.Drawing.Font("Microsoft Sans Serif", 8.25F, System.Drawing.FontStyle.Bold, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.tbClearResults.Location = new System.Drawing.Point(78, 247);
            this.tbClearResults.Name = "tbClearResults";
            this.tbClearResults.Size = new System.Drawing.Size(50, 21);
            this.tbClearResults.TabIndex = 2;
            this.tbClearResults.Text = "Clear";
            this.tbClearResults.UseVisualStyleBackColor = true;
            this.tbClearResults.Click += new System.EventHandler(this.tbClearResults_Click);
            // 
            // Form1
            // 
            this.AutoScaleDimensions = new System.Drawing.SizeF(6F, 13F);
            this.AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font;
            this.ClientSize = new System.Drawing.Size(562, 502);
            this.Controls.Add(this.tbDestMac);
            this.Controls.Add(this.tbSourceMac);
            this.Controls.Add(this.tbTimeToLive);
            this.Controls.Add(this.tbIdNo);
            this.Controls.Add(this.tbWinLen);
            this.Controls.Add(this.tbNumOfPackets);
            this.Controls.Add(this.tbAckNo);
            this.Controls.Add(this.tbSeqNo);
            this.Controls.Add(this.gbFlags);
            this.Controls.Add(this.tbSourcePort);
            this.Controls.Add(this.tbDestPort);
            this.Controls.Add(this.tbSourceIP);
            this.Controls.Add(this.txtData);
            this.Controls.Add(this.pbr);
            this.Controls.Add(this.label3);
            this.Controls.Add(this.cbAdapter);
            this.Controls.Add(this.btnCancel);
            this.Controls.Add(this.label6);
            this.Controls.Add(this.tbClearResults);
            this.Controls.Add(this.btnAttack);
            this.Controls.Add(this.label4);
            this.Controls.Add(this.label2);
            this.Controls.Add(this.label7);
            this.Controls.Add(this.label5);
            this.Controls.Add(this.label13);
            this.Controls.Add(this.label15);
            this.Controls.Add(this.label12);
            this.Controls.Add(this.label14);
            this.Controls.Add(this.label11);
            this.Controls.Add(this.label10);
            this.Controls.Add(this.label9);
            this.Controls.Add(this.label8);
            this.Controls.Add(this.label1);
            this.Controls.Add(this.tbResults);
            this.Controls.Add(this.tbTarget);
            this.Controls.Add(this.derp);
            this.FormBorderStyle = System.Windows.Forms.FormBorderStyle.Fixed3D;
            this.Icon = ((System.Drawing.Icon)(resources.GetObject("$this.Icon")));
            this.MaximizeBox = false;
            this.Name = "Form1";
            this.StartPosition = System.Windows.Forms.FormStartPosition.CenterScreen;
            this.Text = "Joe\'s Raw TCP Packet Maker";
            this.Load += new System.EventHandler(this.Form1_Load);
            this.gbFlags.ResumeLayout(false);
            this.gbFlags.PerformLayout();
            this.derp.ResumeLayout(false);
            this.derp.PerformLayout();
            this.ResumeLayout(false);
            this.PerformLayout();

        }

        #endregion

        private System.Windows.Forms.TextBox tbTarget;
        private System.Windows.Forms.Label label1;
        private System.Windows.Forms.Button btnAttack;
        private System.Windows.Forms.TextBox tbResults;
        private System.Windows.Forms.Label label2;
        private System.Windows.Forms.ComboBox cbAdapter;
        private System.Windows.Forms.Label label3;
        private System.Windows.Forms.ProgressBar pbr;
        private System.ComponentModel.BackgroundWorker bgw;
        private System.Windows.Forms.Button btnCancel;
        private System.Windows.Forms.TextBox txtData;
        private System.Windows.Forms.Label label4;
        private System.Windows.Forms.TextBox tbDestPort;
        private System.Windows.Forms.Label label5;
        private System.Windows.Forms.Label label6;
        private System.Windows.Forms.TextBox tbSourceIP;
        private System.Windows.Forms.Label label7;
        private System.Windows.Forms.TextBox tbSourcePort;
        private System.Windows.Forms.GroupBox gbFlags;
        private System.Windows.Forms.CheckBox cbNs;
        private System.Windows.Forms.CheckBox cbCwr;
        private System.Windows.Forms.CheckBox cbEnc;
        private System.Windows.Forms.CheckBox cbPsh;
        private System.Windows.Forms.CheckBox cbRst;
        private System.Windows.Forms.CheckBox cbUrg;
        private System.Windows.Forms.CheckBox cbFin;
        private System.Windows.Forms.CheckBox cbAck;
        private System.Windows.Forms.CheckBox cbSyn;
        private System.Windows.Forms.CheckBox cbNone;
        private System.Windows.Forms.TextBox tbSeqNo;
        private System.Windows.Forms.TextBox tbAckNo;
        private System.Windows.Forms.TextBox tbNumOfPackets;
        private System.Windows.Forms.TextBox tbWinLen;
        private System.Windows.Forms.TextBox tbSourceMac;
        private System.Windows.Forms.TextBox tbDestMac;
        private System.Windows.Forms.Label label8;
        private System.Windows.Forms.Label label9;
        private System.Windows.Forms.Label label10;
        private System.Windows.Forms.Label label11;
        private System.Windows.Forms.Label label12;
        private System.Windows.Forms.Label label13;
        private System.Windows.Forms.Label label14;
        private System.Windows.Forms.Label label15;
        private System.Windows.Forms.TextBox tbIdNo;
        private System.Windows.Forms.TextBox tbTimeToLive;
        private System.Windows.Forms.MenuStrip derp;
        private System.Windows.Forms.ToolStripMenuItem helpToolStripMenuItem;
        private System.Windows.Forms.ToolStripMenuItem srslyHELPToolStripMenuItem;
        private System.Windows.Forms.ToolStripMenuItem aboutToolStripMenuItem;
        private System.Windows.Forms.ToolStripMenuItem aboutMyAppToolStripMenuItem;
        private System.Windows.Forms.ToolStripMenuItem visitSiteToolStripMenuItem;
        private System.Windows.Forms.Button tbClearResults;
    }
}

