#include "splashscreen.h"
#include "clientversion.h"
#include "util.h"
#include <QLabel>
#include <QMovie>
#include <QPainter>
#undef loop /* ugh, remove this when the #define loop is gone from util.h */
#include <QApplication>

SplashScreen::SplashScreen(const QPixmap &pixmap, Qt::WindowFlags f) :
    QSplashScreen(pixmap, f)
{
	
	// set reference point, paddings
    int paddingLeftCol2         = 119;
    int paddingTopCol2          = 105;
    int line1 = 0;
    int line2 = 13;
    int line3 = 26;

    float fontFactor            = 1.0;

    // define text to place
    QString titleText       = QString(QApplication::applicationName()).replace(QString("-testnet"), QString(""), Qt::CaseSensitive); // cut of testnet, place it as single object further down
    QString versionText     = QString("Version %1 ").arg(QString::fromStdString(FormatFullVersion()));
    QString copyrightText1   = QChar(0xA9)+QString(" 2009-%1 ").arg(COPYRIGHT_YEAR) + QString(tr("The Bitcoin developers"));
    QString copyrightText2   = QChar(0xA9)+QString(" 2013-%1 ").arg(COPYRIGHT_YEAR) + QString(tr("The BitNet developers"));

    QString font            = "Arial";

    // load the bitmap for writing some text over it
    QPixmap newPixmap;
    if(GetBoolArg("-testnet")) {
        newPixmap     = QPixmap(":/images/splash");	//QPixmap(":/images/splash_testnet");
    }
    else {
        newPixmap     = QPixmap(":/images/splash");
    }

    QPainter pixPaint(&newPixmap);
    pixPaint.setPen(QColor(255, 255, 255));	//pixPaint.setPen(QColor(70,70,70));

    pixPaint.setFont(QFont(font, 10*fontFactor));
    pixPaint.drawText(paddingLeftCol2,paddingTopCol2+line3,versionText);

    // draw copyright stuff
    pixPaint.setFont(QFont(font, 10*fontFactor));
    pixPaint.drawText(paddingLeftCol2,paddingTopCol2+line1,copyrightText1);
    pixPaint.drawText(paddingLeftCol2,paddingTopCol2+line2,copyrightText2);

    pixPaint.end();

    this->setContentsMargins(0,0,0,0);    
    QLabel *movieLabel = new QLabel(this);
	movieLabel->setContentsMargins(0,0,0,0);	
	movieLabel->setFixedSize(400, 450);
	movieLabel->setAlignment(Qt::AlignCenter | Qt::AlignVCenter);
    QMovie *movie = new QMovie("vpncoin.gif");
	movieLabel->setMovie( movie );
	movie->start();
	movieLabel->show();

    this->setPixmap(newPixmap);
	
}
QWidget *gwMain=NULL;
void SplashScreen::DelayFinish(QWidget *wMain, int deLay)
{
    gwMain = wMain;
	movieTimer = new QTimer();
	movieTimer->setInterval(deLay * 1000);	// 3s
	movieTimer->start();
	connect(movieTimer, SIGNAL(timeout()), this, SLOT(finishSplashTimer()));
}

void SplashScreen::finishSplashTimer()
{
	if( gwMain != NULL ){ gwMain->show(); }
	movieTimer->stop();
	this->finish(gwMain);
}
