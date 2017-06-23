import _ from 'lodash'
require( 'index.html' )
require( 'css/_globals.scss' )
require( 'css/main.scss' )

!(function () {
	const TOP_TRIGGER = 50
	const NAV_LINKS = [
		'HELLO!',
		'WHEN & WHERE',
		'WHERE TO STAY',
		'IRVINE',
		'CELEBRATION',
		'OUR JOURNEY',
		'REGISTRY',
		'RSVP'
	]

	function init() {
		var ul = document.querySelectorAll( '#nav-bar .nav-list' )
		if ( ul ) ul = ul[0]

		NAV_LINKS.forEach( function ( link ) {
			var li = document.createElement( 'li' )
			li.setAttribute( 'class', 'link nav-link' )
			li.innerText = link
			li.addEventListener( 'click', onNavClick )
			ul.append( li )
		})

		console.log( ul )
	}
	init()

	var gondola = document.getElementById( 'gondola' )
	var mountains = _.map( document.getElementsByClassName( 'mountain' ) )
	window.addEventListener( 'load', function ( e ) {
		window.scrollTo( 0, Number.MAX_VALUE )
		document.getElementsByTagName( 'main' )[0].className = 'scene fade-in'
	})

	var height = document.body.clientHeight
	var center = mountains[0]
	var left = mountains[1]
	var right = mountains[2]

	var info = document.getElementById( 'info-overlay' )


	window.addEventListener( 'scroll', function ( e ) {
		var currentY = window.top.scrollY
		var winHeight = window.screen.height
		var percent = ( 1 - ( currentY + winHeight ) / height ) / 1.5

		left.translateX = 150 * percent * -1
		left.translateY = 0

		right.translateX = 150 * percent
		right.translateY = 0

		center.translateX = percent * -10
		center.translateY = percent * 100 / 3

		left.scale = percent + 2.4
		right.scale = percent + 2.4
		center.scale = percent * 6 + 2.4

		checkTop( currentY )
	})

	function frame( time ) {
		mountains.forEach( function ( mount ) {
			var transform = 'scale('+ mount.scale +')'
			transform += ' translateX('+ mount.translateX +'%)'
			transform += ' translateY('+ mount.translateY +'%)'

			mount.style.transform = transform
		})
		requestAnimationFrame( frame )
	}
	requestAnimationFrame( frame )

	function checkTop( y ) {
		if ( y < TOP_TRIGGER ) {
			info.style.opacity = '1'
			info.style.visibility = 'visible'
			// document.body.style.backgroundColor = 'white'
		} else {
			info.style.opacity = '0'
			document.body.style.backgroundColor = 'skyblue'
		}
	}

	function onNavClick( nav ) {
		console.log( nav )
	}







	window.left = left
	window.right = right
	window.center = center
	window.mountains = mountains


	window.addEventListener( 'beforeunload', function ( e ) {
		window.scrollTo( 0, Number.MAX_VALUE )
	})
})()

function changeURLRoute(argument) {
	// body...
}

function changeURLParams( paramsObj ) {
    var path = window.location.pathname
    var params = {}
    try {
        var paramsString = /\?.*/.exec( window.location.href )[0]
        var paramsArray = paramsString.replace( /\?/, '').split( '&' )
        paramsArray.forEach( function ( singleParam ) {
            var paramPair = singleParam.split( '=' )
            params[paramPair[0]] = ''
            for ( var i = 1; i < paramPair.length; i++ ) {
                params[paramPair[0]] += paramPair[i]
            }
        })
    } catch ( e ) {
        // No params
    }

    params = Object.assign( {}, params, paramsObj )
    var finalParams = []

    for( var key in params ) {
        if ( paramsObj[key] ) {
            params[key] = paramsObj[key]
        }
        var paramKey = key +'='+ params[key]
        finalParams.push( paramKey )
    }
    var finalPath = path +'?'+ finalParams.join( '&' )
    window.history.pushState("{}", "", finalPath )
    return finalPath
    // angular overrides this
};

window.changeURLParams = changeURLParams
